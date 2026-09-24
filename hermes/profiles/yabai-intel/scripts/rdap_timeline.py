#!/usr/bin/env python3
"""RDAP/whois timeline collector for the yabai-intel bot.

SecurityTrails-style time series, built from authoritative sources only:
for each tracked domain, fetch the RDAP record (rdap.org bootstrap) every
run and append a dated snapshot to an append-only JSONL timeline. Changed
fields (registrar, status, nameservers, expiry) become timeline events.

PII guardrail (SOUL.md rule 2): RDAP entity names that look like natural
persons are stored as `(個人登録のため非掲載)`. Organization handles,
countries, and statuses are kept. Vcard N-type entries are redacted when
the FN field is a personal-looking name with no ORG.

The timeline file is the wiki's source of truth: the agent reads it and
writes prose entries citing the snapshot dates, never raw PII.
"""
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from throttle import gate, mark  # noqa: E402

STATE_DIR = os.path.expanduser("~/.hermes/profiles/yabai-intel/state")
TIMELINE = os.path.join(STATE_DIR, "rdap_timeline.jsonl")
# Domains this workspace operates or tracks. Extending this list is a
# human decision (each entry is a domain we will keep a public timeline
# of) — the bot does not add domains to it.
DOMAINS = [
    "kotobase.net", "itonami.cloud", "junkawasaki.com",
    "awai.network", "kotoba-lang.org",
    # 追跡対象 (オーナー指示 2026-09-13): 詐欺会社疑い — RDAP/whois 変遷を timeline 化
    "nba-limited.com",
]
REDACT = "(個人登録のため非掲載)"
TIMEOUT = 45
WATCH_FIELDS = ["status", "registrar", "nameservers", "expires", "handle"]


def fetch_rdap(domain):
    url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json",
        "User-Agent": "yabai-intel/1.0 (kotobase wiki RDAP timeline)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read())


def redact_entities(entities):
    """Keep org/handle/country, redact natural-person names."""
    out = []
    for e in entities or []:
        roles = e.get("roles", [])
        vcard = (e.get("vcardArray") or [None, []])[1]
        fn = None
        org = None
        for item in vcard:
            if item[0] == "fn":
                fn = item[3]
            elif item[0] == "org":
                org = item[3]
        # A vcard with an ORG is an org contact; a bare FN with none is a
        # person under ICANN's profile and gets redacted.
        if fn and not org:
            fn = REDACT
        out.append({"roles": roles, "handle": e.get("handle"),
                    "fn": fn, "org": org})
    return out


def snapshot(domain, j):
    ns = [n.get("ldhName") for n in (j.get("nameservers") or [])]
    registrar = None
    for e in j.get("entities") or []:
        if "registrar" in (e.get("roles") or []):
            vcard = (e.get("vcardArray") or [None, []])[1]
            for item in vcard:
                if item[0] == "fn":
                    registrar = item[3]
    events = j.get("events") or []
    expires = next((e.get("eventDate") for e in events
                    if e.get("eventAction") == "expiration"), None)
    return {
        "domain": domain,
        "observed": datetime.now(timezone.utc).isoformat(),
        "handle": j.get("handle"),
        "status": j.get("status"),
        "registrar": registrar,
        "nameservers": sorted(n for n in ns if n),
        "expires": expires,
        "entities": redact_entities(j.get("entities")),
    }


def diff(prev, cur):
    if not prev:
        return {"initial": True}
    changes = {}
    for f in WATCH_FIELDS:
        if prev.get(f) != cur.get(f):
            changes[f] = {"from": prev.get(f), "to": cur.get(f)}
    return changes


def main():
    gate("yabai-intel-rdap", hours=12)
    os.makedirs(STATE_DIR, exist_ok=True)
    prev = {}
    if os.path.exists(TIMELINE):
        with open(TIMELINE) as f:
            for line in f:
                try:
                    row = json.loads(line)
                    prev[row["domain"]] = row
                except Exception:
                    continue
    appended = 0
    lines_out = []
    for d in DOMAINS:
        try:
            j = fetch_rdap(d)
        except Exception as e:
            print(f"REFUSED — RDAP unreachable for {d}: {e}")
            return 0  # bot must RUN and be told it is blind
        snap = snapshot(d, j)
        changes = diff(prev.get(d), snap)
        row = dict(snap)
        row["changes"] = changes
        lines_out.append(json.dumps(row, ensure_ascii=False))
        appended += 1
        tag = "CHANGED" if (changes and not changes.get("initial")) else "unchanged" \
            if prev.get(d) else "first-observation"
        print(f"rdap\t{d}\t{tag}\tregistrar={snap['registrar']}\t"
              f"status={','.join(snap['status'] or [])}")
    with open(TIMELINE, "a") as f:
        for line in lines_out:
            f.write(line + "\n")
    print(f"timeline\t{TIMELINE}\tappended={appended}")
    print("Timeline rows with changes are the events to write up in the wiki's "
          "運営会社 pages — cite the observed date, never raw registrant PII.")
    mark("yabai-intel-rdap")
    return 0


if __name__ == "__main__":
    sys.exit(main())
