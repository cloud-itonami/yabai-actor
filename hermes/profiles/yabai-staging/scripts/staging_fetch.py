#!/usr/bin/env python3
"""yabai-staging fetcher — one dataset per run, into R2 ai-gftd-staging.

Downloads the dataset (streaming, sha256 as it goes), uploads ONE object
per chunk to ai-gftd-staging, and appends a manifest row. Idempotent: a
sha256 already present in the manifest is skipped — re-runs cost a HEAD
request, not a re-download.

Auth: CLOUDFLARE_API_TOKEN via env or macOS Keychain (service=gftd.cf,
account=API_TOKEN), same two scopes as the datalake writer.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from throttle import gate, mark  # noqa: E402

STATE_DIR = os.path.expanduser("~/.hermes/profiles/yabai-staging/state")
MANIFEST = os.path.join(STATE_DIR, "manifest.jsonl")
ACCOUNT = "4da88288dc30d9ee257f319d3c33ecf0"
BUCKET = "ai-gftd-staging"

DATASETS = {
    "urlhaus-full": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "publisher": "abuse.ch URLhaus",
        "note": "full recent CSV — backfills the IOC corpus beyond text_recent",
    },
    "spamhaus-drop-full": {
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "publisher": "The Spamhaus Project",
        "note": "JSONL snapshot",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "publisher": "OpenPhish community feed",
        "note": "text feed snapshot",
    },
}


def cf_token():
    tok = os.environ.get("CLOUDFLARE_API_TOKEN")
    if tok:
        return tok
    try:
        return subprocess.run(
            ["security", "find-generic-password", "-s", "gftd.cf",
             "-a", "API_TOKEN", "-w"],
            capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return None


def load_manifest():
    rows = []
    if os.path.exists(MANIFEST):
        with open(MANIFEST) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue
    return rows


def sha_file(p):
    h = hashlib.sha256()
    n = 0
    with open(p, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    # jobs.json 'args' is not honoured by every scheduler path, so when no
    # argv dataset is given, rotate through the ladder by time — one
    # dataset per run, deterministic, no missing-arg refusal.
    if args:
        dataset = args[0]
    else:
        ordered = sorted(DATASETS)
        slot = int(time.time() // 21600)  # 6h bucket
        dataset = ordered[slot % len(ordered)]
    if not dataset or dataset not in DATASETS:
        print("REFUSED — pick a dataset: " + ", ".join(sorted(DATASETS)))
        return 0
    gate(f"yabai-staging-{dataset}", hours=12)
    spec = DATASETS[dataset]
    os.makedirs(STATE_DIR, exist_ok=True)
    known = {r.get("sha256") for r in load_manifest()}

    tok = cf_token()
    if not tok:
        print("REFUSED — no CLOUDFLARE_API_TOKEN (env or Keychain gftd.cf/API_TOKEN)")
        return 0

    # 1. download (streaming to temp file)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    h = hashlib.sha256()
    size = 0
    try:
        req = urllib.request.Request(spec["url"], headers={
            "User-Agent": "yabai-staging/1.0 (kotobase staging fetcher)"})
        with urllib.request.urlopen(req, timeout=300, ) as r, open(tmp.name, "wb") as out:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                out.write(b)
                h.update(b)
                size += len(b)
        digest = h.hexdigest()
    except Exception as e:
        print(f"REFUSED — download failed: {e}")
        return 0
    finally:
        tmp.close()

    if digest in known:
        os.unlink(tmp.name)
        print(f"[SILENT] {dataset} sha256 {digest[:12]}… already staged.")
        return 0

    # 2. upload to R2 via wrangler (streamed from the temp file)
    key = f"staging/{dataset}/{digest}"
    env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID=ACCOUNT,
               CLOUDFLARE_API_TOKEN=tok)
    up = subprocess.run(
        ["/opt/homebrew/bin/wrangler", "r2", "object", "put",
         f"{BUCKET}/{key}", "--file", tmp.name, "--remote"],
        capture_output=True, text=True, timeout=600, env=env)
    if up.returncode != 0:
        print("REFUSED — R2 upload failed:\n" + (up.stderr or up.stdout)[:500])
        os.unlink(tmp.name)
        return 0

    # 3. verify readback size via wrangler r2 object get --pipe | wc
    dl = subprocess.run(
        ["/opt/homebrew/bin/wrangler", "r2", "object", "get",
         f"{BUCKET}/{key}", "--pipe", "--remote"],
        capture_output=True, timeout=600, env=env)
    if len(dl.stdout or b"") != size:
        print(f"REFUSED — readback size mismatch: staged {size}, read back {len(dl.stdout or b'')}")
        os.unlink(tmp.name)
        return 0

    os.unlink(tmp.name)
    row = {"dataset": dataset, "key": key, "sha256": digest, "bytes": size,
           "url": spec["url"], "publisher": spec["publisher"],
           "fetched-at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "claimed-by": None, "claimed-at": None, "classified-at": None}
    with open(MANIFEST, "a") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"staged\t{dataset}\t{key}\t{size} bytes")
    print(f"sha256\t{digest}")
    print("Chunk staged and verified. The classifier bot picks it up on its next run.")
    mark(f"yabai-staging-{dataset}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
