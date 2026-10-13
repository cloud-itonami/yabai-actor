#!/usr/bin/env hy
"Evidence script for the yabai-intel bot.

Pulls public threat-intelligence feeds (URLhaus recent additions, Spamhaus
DROP, OpenPhish community feed) and prints the NEW entries the bot has not
yet recorded to the wiki's 迷惑インフラ section. Decision-free: measures
what is available; the agent decides what to write and where, within the
SOUL.md guardrails (IOC-only, source-mandatory, no PII).

REFUSED banner on any failure so the bot is told it is blind, never that
the feeds were empty.
"
(import hashlib)
(import json)
(import os)
(import sys)
(import urllib.request)
(import datetime [datetime timezone])
((. sys.path insert) 0
  ((. os.path dirname) ((. os.path abspath) __file__)))
(import throttle [gate mark])
(setv STATE_DIR ((. os.path expanduser) "~/.hermes/profiles/yabai-intel/state"))
(setv SEEN ((. os.path join) STATE_DIR "seen_feeds.json"))
(setv FEEDS [#("urlhaus" "https://urlhaus.abuse.ch/downloads/text_recent/") #("spamhaus_drop" "https://www.spamhaus.org/drop/drop_v4.json") #("openphish" "https://openphish.com/feed.txt")])
(setv TIMEOUT 60)

(defn fetch [url]
  (setv req ((. urllib.request Request) url :headers {"User-Agent" "yabai-intel/1.0 (kotobase wiki collector)"}))
  (with [r ((. urllib.request urlopen) req :timeout TIMEOUT)]
    (return (r.read))))

(defn load_seen []
  (try
   (with [f (open SEEN)]
     (return (json.load f)))
   (except [Exception] (return {}))))

(defn main []
  (gate "yabai-intel-feeds" :hours 6)
  (os.makedirs STATE_DIR :exist_ok True)
  (setv seen (load_seen))
  (seen.setdefault "entries" {})
  (setv lines [])
  (setv total_new 0)
  (for [#(name url) FEEDS]
    (try
     (setv body (fetch url))
     (except [e Exception] (print f"REFUSED — feed {name} unreachable: {e}") (return 0)))
    (setv digest ((. (hashlib.sha256 body) hexdigest)))
    (setv prev ((. ((. (get seen "entries") get) name {}) get) "sha256"))
    (setv count
      (sum (gfor _ (body.splitlines) :if (_.strip) 1)))
    (setv changed (!= digest prev))
    (setv (get (get seen "entries") name)
      {"sha256"  digest
       "fetched" ((. (datetime.now timezone.utc) isoformat))
       "rows"    count})
    (lines.append f"{name}\trows={count}\t{(if changed "CHANGED" "unchanged")}\t{url}")
    (when changed (+= total_new 1)))
  (when (= total_new 0) (print "[SILENT] all feeds unchanged since last run.") (return 0))
  (with [f (open SEEN "w")]
    (json.dump seen f :indent 1))
  (print "feed\tstatus\turl")
  (print ((. "\n" join) lines))
  (print f"feeds_changed\t{total_new}")
  (print "NEW feed content detected — the changed feeds are re-fetchable from the urls above. Record new IOC entries to the wiki with sources; never without them.")
  (mark "yabai-intel-feeds")
  (return 0))

(when (= __name__ "__main__") (sys.exit (main)))