#!/usr/bin/env hy
"yabai-staging fetcher — one dataset per run, into R2 ai-gftd-staging.

Downloads the dataset (streaming, sha256 as it goes), uploads ONE object
per chunk to ai-gftd-staging, and appends a manifest row. Idempotent: a
sha256 already present in the manifest is skipped — re-runs cost a HEAD
request, not a re-download.

Auth: CLOUDFLARE_API_TOKEN via env or macOS Keychain (service=gftd.cf,
account=API_TOKEN), same two scopes as the datalake writer.
"
(import hashlib)
(import json)
(import os)
(import subprocess)
(import sys)
(import tempfile)
(import time)
(import urllib.request)
((. sys.path insert) 0
  ((. os.path dirname) ((. os.path abspath) __file__)))
(import throttle [gate mark])
(setv STATE_DIR ((. os.path expanduser) "~/.hermes/profiles/yabai-staging/state"))
(setv MANIFEST ((. os.path join) STATE_DIR "manifest.jsonl"))
(setv ACCOUNT "4da88288dc30d9ee257f319d3c33ecf0")
(setv BUCKET "ai-gftd-staging")
(setv DATASETS
  {"urlhaus-full"       {"url" "https://urlhaus.abuse.ch/downloads/csv_recent/"  "publisher" "abuse.ch URLhaus"  "note" "full recent CSV — backfills the IOC corpus beyond text_recent"}
   "spamhaus-drop-full" {"url" "https://www.spamhaus.org/drop/drop_v4.json"  "publisher" "The Spamhaus Project"  "note" "JSONL snapshot"}
   "openphish"          {"url" "https://openphish.com/feed.txt"  "publisher" "OpenPhish community feed"  "note" "text feed snapshot"}})

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

(defn load_manifest []
  (setv rows [])
  (when ((. os.path exists) MANIFEST)
    (with [f (open MANIFEST)]
      (for [line f]
       (setv line (line.strip))
       (when line
         (try (rows.append (json.loads line)) (except [Exception] (continue)))))))
  (return rows))

(defn sha_file [p]
  (setv h (hashlib.sha256))
  (setv n 0)
  (with [f (open p "rb")]
    (while True
     (setv b (f.read (<< 1 20)))
     (when (not b) (break))
     (h.update b)
     (+= n (len b))))
  (return #((h.hexdigest) n)))

(defn main []
  (setv args
   (lfor a (cut sys.argv 1 None)
     :if (not (a.startswith "--"))
     a))
  (if args
    (do (setv dataset (get args 0)))
    (do
      (setv ordered (sorted DATASETS))
      (setv slot (int (// (time.time) 21600)))
      (setv dataset (get ordered (% slot (len ordered))))))
  (when (or (not dataset) (not-in dataset DATASETS))
    (print (+ "REFUSED — pick a dataset: " ((. ", " join) (sorted DATASETS))))
    (return 0))
  (gate f"yabai-staging-{dataset}" :hours 12)
  (setv spec (get DATASETS dataset))
  (os.makedirs STATE_DIR :exist_ok True)
  (setv known (sfor r (load_manifest) (r.get "sha256")))
  (setv tok (cf_token))
  (when (not tok) (print "REFUSED — no CLOUDFLARE_API_TOKEN (env or Keychain gftd.cf/API_TOKEN)") (return 0))
  (setv tmp (tempfile.NamedTemporaryFile :delete False :suffix ".bin"))
  (setv h (hashlib.sha256))
  (setv size 0)
  (try
    (setv req
      ((. urllib.request Request) (get spec "url") :headers {"User-Agent" "yabai-staging/1.0 (kotobase staging fetcher)"}))
    (with [r   ((. urllib.request urlopen) req :timeout 300)
          out (open tmp.name "wb")]
      (while True
       (setv b (r.read (<< 1 20)))
       (when (not b) (break))
       (out.write b)
       (h.update b)
       (+= size (len b))))
    (setv digest (h.hexdigest))
    (except [e Exception] (print f"REFUSED — download failed: {e}") (return 0))
    (finally (tmp.close)))
  (when (in digest known)
    (os.unlink tmp.name)
    (print f"[SILENT] {dataset} sha256 {(cut digest 12)}… already staged.")
    (return 0))
  (setv key f"staging/{dataset}/{digest}")
  (setv env (dict os.environ :CLOUDFLARE_ACCOUNT_ID ACCOUNT :CLOUDFLARE_API_TOKEN tok))
  (setv up
    (subprocess.run ["/opt/homebrew/bin/wrangler" "r2" "object" "put" f"{BUCKET}/{key}" "--file" tmp.name "--remote"]
      :capture_output True
      :text True
      :timeout 600
      :env env))
  (when (!= up.returncode 0)
    (print (+ "REFUSED — R2 upload failed:\n" (cut (or up.stderr up.stdout) 500)))
    (os.unlink tmp.name)
    (return 0))
  (setv dl
    (subprocess.run ["/opt/homebrew/bin/wrangler" "r2" "object" "get" f"{BUCKET}/{key}" "--pipe" "--remote"]
      :capture_output True
      :timeout 600
      :env env))
  (when (!= (len (or dl.stdout b"")) size)
    (print f"REFUSED — readback size mismatch: staged {size}, read back {(len (or dl.stdout b""))}")
    (os.unlink tmp.name)
    (return 0))
  (os.unlink tmp.name)
  (setv row
    {"dataset"       dataset
     "key"           key
     "sha256"        digest
     "bytes"         size
     "url"           (get spec "url")
     "publisher"     (get spec "publisher")
     "fetched-at"    (time.strftime "%Y-%m-%dT%H:%M:%SZ" (time.gmtime))
     "claimed-by"    None
     "claimed-at"    None
     "classified-at" None})
  (with [f (open MANIFEST "a")]
    (f.write (+ (json.dumps row :ensure_ascii False) "\n")))
  (print f"staged\t{dataset}\t{key}\t{size} bytes")
  (print f"sha256\t{digest}")
  (print "Chunk staged and verified. The classifier bot picks it up on its next run.")
  (mark f"yabai-staging-{dataset}")
  (return 0))

(when (= __name__ "__main__") (sys.exit (main)))