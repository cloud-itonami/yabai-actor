#!/usr/bin/env hy
"yabai-classify — claim ONE staging chunk per run, parse, emit candidates.

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
"
(import fcntl)
(import json)
(import os)
(import subprocess)
(import sys)
(import time)
((. sys.path insert) 0
  ((. os.path dirname) ((. os.path abspath) __file__)))
(import throttle [gate mark])
(setv STATE_DIR ((. os.path expanduser) "~/.hermes/profiles/yabai-classify/state"))
(setv LOCK ((. os.path join) STATE_DIR ".classify.lock"))
(setv ACCOUNT "4da88288dc30d9ee257f319d3c33ecf0")
(setv BUCKET "ai-gftd-staging")

(defn cf_token []
  (setv tok ((. os.environ get) "CLOUDFLARE_API_TOKEN"))
  (when tok (return tok))
  (try
    (return
      ((. (. (subprocess.run ["security" "find-generic-password" "-s" "gftd.cf" "-a" "API_TOKEN" "-w"]
               :capture_output True
               :text True
               :timeout 15)
            stdout) strip)))
    (except [Exception] (return None))))

(defn main []
  (gate "yabai-classify" :hours 1)
  (os.makedirs STATE_DIR :exist_ok True)
  (setv staging_manifest ((. os.path expanduser) "~/.hermes/profiles/yabai-staging/state/manifest.jsonl"))
  (when (not ((. os.path exists) staging_manifest))
    (print (+ "REFUSED — no staging manifest at " staging_manifest))
    (return 0))
  (setv lock (open LOCK "w"))
  (try
    (fcntl.flock lock (| fcntl.LOCK_EX fcntl.LOCK_NB))
    (except [OSError] (print "[SILENT] THROTTLED — another classify run holds the lock.") (return 0)))
  (setv rows [])
  (with [f (open staging_manifest)]
    (for [line f]
     (setv line (line.strip))
     (when line (rows.append (json.loads line)))))
  (rows.sort :key (fn [r] (or (r.get "fetched-at") "")))
  (setv target
    (next (gfor r rows :if (not (r.get "claimed-by")) r) None))
  (when (not target) (print "[SILENT] no unclaimed chunks in the staging manifest.") (return 0))
  (setv tok (cf_token))
  (when (not tok) (print "REFUSED — no CLOUDFLARE_API_TOKEN") (return 0))
  (setv (get target "claimed-by") "yabai-classify")
  (setv (get target "claimed-at") (time.strftime "%Y-%m-%dT%H:%M:%SZ" (time.gmtime)))
  (setv tmp (+ staging_manifest ".tmp"))
  (with [f (open tmp "w")]
    (for [r rows]
     (f.write (+ (json.dumps r :ensure_ascii False) "\n"))))
  (os.replace tmp staging_manifest)
  (setv env (dict os.environ :CLOUDFLARE_ACCOUNT_ID ACCOUNT :CLOUDFLARE_API_TOKEN tok))
  (setv out ((. os.path join) STATE_DIR "current_chunk.bin"))
  (setv dl
    (subprocess.run ["/opt/homebrew/bin/wrangler" "r2" "object" "get" f"{BUCKET}/{(get target "key")}" "--file" out "--remote"]
      :capture_output True
      :text True
      :timeout 600
      :env env))
  (when (!= dl.returncode 0)
    (print (+ "REFUSED — R2 download failed:\n" (cut (or dl.stderr dl.stdout) 400)))
    (return 0))
  (setv size ((. os.path getsize) out))
  (when (!= size (target.get "bytes"))
    (print f"REFUSED — chunk size mismatch:: manifest {(target.get "bytes")}, got {size}")
    (return 0))
  (print f"claimed\t{(get target "dataset")}\t{(get target "key")}")
  (print f"sha256\t{(target.get "sha256")}")
  (print f"local\t{out}\t{size} bytes")
  (print "CANDIDATES\t0\tparser=not-yet-selected")
  (print "Chunk is claimed and on disk. Choose the deterministic parser for this dataset (urlhaus CSV / drop JSONL / openphish text), produce candidate facts in the IOC corpus shape, and route them — never bypass admission, never lift whois-shaped PII into facts.")
  (mark "yabai-classify")
  (return 0))

(when (= __name__ "__main__") (sys.exit (main)))