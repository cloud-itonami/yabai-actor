#!/usr/bin/env hy
"RDAP/whois timeline collector for the yabai-intel bot.

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
(setv TIMELINE ((. os.path join) STATE_DIR "rdap_timeline.jsonl"))
(setv DOMAINS ["kotobase.net" "itonami.cloud" "junkawasaki.com" "awai.network" "kotoba-lang.org" "nba-limited.com"])
(setv REDACT "(個人登録のため非掲載)")
(setv TIMEOUT 45)
(setv WATCH_FIELDS ["status" "registrar" "nameservers" "expires" "handle"])

(defn fetch_rdap [domain]
  (setv url f"https://rdap.org/domain/{domain}")
  (setv req
    ((. urllib.request Request) url :headers {"Accept" "application/rdap+json"  "User-Agent" "yabai-intel/1.0 (kotobase wiki RDAP timeline)"}))
  (with [r ((. urllib.request urlopen) req :timeout TIMEOUT)]
    (return (json.loads (r.read)))))

(defn redact_entities [entities]
  "Keep org/handle/country, redact natural-person names."
  (setv out [])
  (for [e (or entities [])]
    (setv roles (e.get "roles" []))
    (setv vcard (get (or (e.get "vcardArray") [None []]) 1))
    (setv fn None)
    (setv org None)
    (for [item vcard]
      (if (= (get item 0) "fn")
       (do (setv fn (get item 3)))
       (do (when (= (get item 0) "org") (setv org (get item 3))))))
    (when (and fn (not org)) (setv fn REDACT))
    (out.append {"roles" roles  "handle" (e.get "handle")  "fn" fn  "org" org}))
  (return out))

(defn snapshot [domain j]
  (setv ns
   (lfor n (or (j.get "nameservers") [])
     (n.get "ldhName")))
  (setv registrar None)
  (for [e (or (j.get "entities") [])]
    (when (in "registrar" (or (e.get "roles") []))
     (setv vcard (get (or (e.get "vcardArray") [None []]) 1))
     (for [item vcard]
       (when (= (get item 0) "fn") (setv registrar (get item 3))))))
  (setv events (or (j.get "events") []))
  (setv expires
    (next
      (gfor e events
        :if (= (e.get "eventAction") "expiration")
        (e.get "eventDate"))
      None))
  (return
    {"domain"      domain
     "observed"    ((. (datetime.now timezone.utc) isoformat))
     "handle"      (j.get "handle")
     "status"      (j.get "status")
     "registrar"   registrar
     "nameservers" (sorted (gfor n ns :if n n))
     "expires"     expires
     "entities"    (redact_entities (j.get "entities"))}))

(defn diff [prev cur]
  (when (not prev) (return {"initial" True}))
  (setv changes {})
  (for [f WATCH_FIELDS]
    (when (!= (prev.get f) (cur.get f))
     (setv (get changes f)
       {"from" (prev.get f)  "to" (cur.get f)})))
  (return changes))

(defn main []
  (gate "yabai-intel-rdap" :hours 12)
  (os.makedirs STATE_DIR :exist_ok True)
  (setv prev {})
  (when ((. os.path exists) TIMELINE)
    (with [f (open TIMELINE)]
      (for [line f]
       (try
        (setv row (json.loads line))
        (setv (get prev (get row "domain")) row)
        (except [Exception] (continue))))))
  (setv appended 0)
  (setv lines_out [])
  (for [d DOMAINS]
    (try
     (setv j (fetch_rdap d))
     (except [e Exception] (print f"REFUSED — RDAP unreachable for {d}: {e}") (return 0)))
    (setv snap (snapshot d j))
    (setv changes (diff (prev.get d) snap))
    (setv row (dict snap))
    (setv (get row "changes") changes)
    (lines_out.append (json.dumps row :ensure_ascii False))
    (+= appended 1)
    (setv tag
      (if (and changes (not (changes.get "initial")))
        "CHANGED"
        (if (prev.get d) "unchanged" "first-observation")))
    (print
      f"rdap\t{d}\t{tag}\tregistrar={(get snap "registrar")}\tstatus={((. "," join) (or (get snap "status") []))}"))
  (with [f (open TIMELINE "a")]
    (for [line lines_out]
     (f.write (+ line "\n"))))
  (print f"timeline\t{TIMELINE}\tappended={appended}")
  (print "Timeline rows with changes are the events to write up in the wiki's 運営会社 pages — cite the observed date, never raw registrant PII.")
  (mark "yabai-intel-rdap")
  (return 0))

(when (= __name__ "__main__") (sys.exit (main)))