#!/usr/bin/env python3
"""Evidence script for the yabai-intel bot.

Pulls public threat-intelligence feeds (URLhaus recent additions, Spamhaus
DROP, OpenPhish community feed) and prints the NEW entries the bot has not
yet recorded to the wiki's 迷惑インフラ section. Decision-free: measures
what is available; the agent decides what to write and where, within the
SOUL.md guardrails (IOC-only, source-mandatory, no PII).

REFUSED banner on any failure so the bot is told it is blind, never that
the feeds were empty.
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
SEEN = os.path.join(STATE_DIR, "seen_feeds.json")
FEEDS = [
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/text_recent/"),
    ("spamhaus_drop", "https://www.spamhaus.org/drop/drop_v4.json"),
    ("openphish", "https://openphish.com/feed.txt"),
]
TIMEOUT = 60


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "yabai-intel/1.0 (kotobase wiki collector)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def load_seen():
    try:
        with open(SEEN) as f:
            return json.load(f)
    except Exception:
        return {}


def main():
    gate("yabai-intel-feeds", hours=6)
    os.makedirs(STATE_DIR, exist_ok=True)
    seen = load_seen()
    seen.setdefault("entries", {})
    lines = []
    total_new = 0
    for name, url in FEEDS:
        try:
            body = fetch(url)
        except Exception as e:
            print(f"REFUSED — feed {name} unreachable: {e}")
            return 0  # bot must RUN and be told it is blind
        digest = hashlib.sha256(body).hexdigest()
        prev = seen["entries"].get(name, {}).get("sha256")
        count = sum(1 for _ in body.splitlines() if _.strip())
        changed = digest != prev
        seen["entries"][name] = {
            "sha256": digest,
            "fetched": datetime.now(timezone.utc).isoformat(),
            "rows": count,
        }
        lines.append(f"{name}\trows={count}\t{'CHANGED' if changed else 'unchanged'}\t{url}")
        if changed:
            total_new += 1
    if total_new == 0:
        print("[SILENT] all feeds unchanged since last run.")
        return 0
    with open(SEEN, "w") as f:
        json.dump(seen, f, indent=1)
    print("feed\tstatus\turl")
    print("\n".join(lines))
    print(f"feeds_changed\t{total_new}")
    print("NEW feed content detected — the changed feeds are re-fetchable from the urls above. Record new IOC entries to the wiki with sources; never without them.")
    mark("yabai-intel-feeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
