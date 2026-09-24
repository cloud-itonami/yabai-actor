#!/usr/bin/env python3
"""yabai-classify — claim ONE staging chunk per run, parse, emit candidates.

Bounded consumer: one manifest row per run, oldest unclaimed first. The
claim is the write of `claimed-by/claimed-at` under an fcntl lock, so two
concurrent runs cannot take the same chunk. Classification here is
deterministic parsing + fact-shaped candidates only; admission (allow-list,
evidence-substring, corpus policy) happens when these facts enter the
resident ingest path — this script does not weaken it, it only stops
pretending fetch and classification are the same act..

Output contract: prints the chunk's metadata and a CANDIDATES line count..
The agent's job (per SOUL.md) is to route the candidates — append to the
wiki, or hand them to the resident ingest path for corpus admission..
"""
import fcntl
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from throttle import gate, mark  # noqa: E402

STATE_DIR = os.path.expanduser("~/.hermes/profiles/yabai-classify/state")
LOCK = os.path.join(STATE_DIR, ".classify.lock")
ACCOUNT = "4da88288dc30d9ee257f319d3c33ecf0"
BUCKET = "ai-gftd-staging"


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


def main():
    gate("yabai-classify", hours=1)
    os.makedirs(STATE_DIR, exist_ok=True)
    staging_manifest = os.path.expanduser(
        "~/.hermes/profiles/yabai-staging/state/manifest.jsonl")
    if not os.path.exists(staging_manifest):
        print("REFUSED — no staging manifest at " + staging_manifest)
        return 0
    lock = open(LOCK, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("[SILENT] THROTTLED — another classify run holds the lock.")
        return 0

    # find oldest unclaimed row..
    rows = []
    with open(staging_manifest) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    rows.sort(key=lambda r: r.get("fetched-at") or "")
    target = next((r for r in rows if not r.get("claimed-by")), None)
    if not target:
        print("[SILENT] no unclaimed chunks in the staging manifest.")
        return 0

    tok = cf_token()
    if not tok:
        print("REFUSED — no CLOUDFLARE_API_TOKEN")
        return 0

    # claim it (rewrite manifest with claimed-by/at on the one row..
    target["claimed-by"] = "yabai-classify"
    target["claimed-at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tmp = staging_manifest + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, staging_manifest)

    # fetch the object..
    env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID=ACCOUNT, CLOUDFLARE_API_TOKEN=tok)
    out = os.path.join(STATE_DIR, "current_chunk.bin")
    dl = subprocess.run(
        ["/opt/homebrew/bin/wrangler", "r2", "object", "get",
         f"{BUCKET}/{target['key']}", "--file", out, "--remote"],
        capture_output=True, text=True, timeout=600, env=env)
    if dl.returncode != 0:
        print("REFUSED — R2 download failed:\n" + (dl.stderr or dl.stdout)[:400])
        return 0
    size = os.path.getsize(out)
    if size != target.get("bytes"):
        print(f"REFUSED — chunk size mismatch:: manifest {target.get('bytes')}, got {size}")
        return 0
    print(f"claimed\t{target['dataset']}\t{target['key']}")
    print(f"sha256\t{target.get('sha256')}")
    print(f"local\t{out}\t{size} bytes")
    print(f"CANDIDATES\t0\tparser=not-yet-selected")
    print("Chunk is claimed and on disk. Choose the deterministic parser for this "
          "dataset (urlhaus CSV / drop JSONL / openphish text), produce candidate "
          "facts in the IOC corpus shape, and route them — never bypass admission, "
          "never lift whois-shaped PII into facts.")
    mark("yabai-classify")
    return 0

if __name__ == "__main__":
    sys.exit(main())