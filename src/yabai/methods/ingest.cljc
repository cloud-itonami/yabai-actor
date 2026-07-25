(ns yabai.methods.ingest
  "ingest.py — yabai ACTIVE CTI / passive-DNS collector → kotoba EAVT.
  1:1 Clojure port of `methods/ingest.py` (ADR-2605301400 §T3).

  Defensive threat-intel collector. Pulls PUBLIC CTI surfaces and normalizes them into the
  passive-dns-cti kotoba vocabulary (:domain/* :pdns/* :tlscert/* :indicator/* …), dedup-merges
  with the curated seed (seed wins on id), and writes a merged EAVT graph analyze.py consumes.

  ACTIVE COLLECTION is operator-gated + offline-default. A live network pull (--live) is
  GATE-G7 (YABAI_OPERATOR_GATE).

  House style: ':…' keyword strings stay strings; pure fns (slug / ip-id / parse-crtsh /
  bridge-pdns / key-of) are portable; a minimal JSON reader is inlined (no cheshire/data.json);
  network + file I/O only behind #?(:clj …). The Python `__main__` CLI driver + live crt.sh fetch
  (urllib) are omitted (noted here): main wires source/in/domain/family/live flags to the
  bridges + the dedup-merge writer."
  (:require [clojure.string :as str]
            [yabai.methods.yabai-edn :as edn]))

(def crtsh "https://crt.sh/?q={q}&output=json")
(def vendor-families #{"securitytrails" "dnsdb" "recordedfuture"})

(defn slug
  "Port of _slug(s): re.sub(r'[^a-z0-9]+','-', str(s).lower()).strip('-')."
  [s]
  (-> (str/lower-case (str s))
      (str/replace #"[^a-z0-9]+" "-")
      (str/replace #"^-+" "")
      (str/replace #"-+$" "")))

(defn ip-id
  "Port of _ip_id(addr)."
  [addr]
  (str "ip." (if (str/includes? addr ":") "v6." "v4.")
       (-> addr (str/replace "." "-") (str/replace ":" "-"))))

;; ── minimal JSON reader (Python json.loads shapes: maps string-keyed, ints→long) ──
(declare json-value)

(defn- skip-ws [^String s i]
  (loop [i i]
    (if (and (< i (count s)) (contains? #{\space \tab \newline \return} (nth s i)))
      (recur (inc i)) i)))

(defn- json-string [^String s i]
  (loop [i (inc i), sb (StringBuilder.)]
    (let [c (nth s i)]
      (cond
        (= c \") [(.toString sb) (inc i)]
        (= c \\)
        (let [e (nth s (inc i))]
          (case e
            \" (do (.append sb \") (recur (+ i 2) sb))
            \\ (do (.append sb \\) (recur (+ i 2) sb))
            \/ (do (.append sb \/) (recur (+ i 2) sb))
            \b (do (.append sb \backspace) (recur (+ i 2) sb))
            \f (do (.append sb \formfeed) (recur (+ i 2) sb))
            \n (do (.append sb \newline) (recur (+ i 2) sb))
            \r (do (.append sb \return) (recur (+ i 2) sb))
            \t (do (.append sb \tab) (recur (+ i 2) sb))
            \u (let [cp (Integer/parseInt (subs s (+ i 2) (+ i 6)) 16)]
                 (.append sb (char cp)) (recur (+ i 6) sb))
            (do (.append sb e) (recur (+ i 2) sb))))
        :else (do (.append sb c) (recur (inc i) sb))))))

(defn- json-number [^String s i]
  (let [end (loop [j i]
              (if (and (< j (count s))
                       (contains? #{\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \+ \- \. \e \E} (nth s j)))
                (recur (inc j)) j))
        tok (subs s i end)]
    [(if (some #{\. \e \E} tok) (Double/parseDouble tok) (Long/parseLong tok)) end]))

(defn- json-array [^String s i]
  (loop [i (skip-ws s (inc i)), out []]
    (if (= (nth s i) \])
      [out (inc i)]
      (let [[v i] (json-value s i)
            i (skip-ws s i)]
        (if (= (nth s i) \,)
          (recur (skip-ws s (inc i)) (conj out v))
          [(conj out v) (inc i)])))))

(defn- json-object [^String s i]
  (loop [i (skip-ws s (inc i)), out {}]
    (if (= (nth s i) \})
      [out (inc i)]
      (let [[k i] (json-string s i)
            i (skip-ws s i)
            [v i] (json-value s (skip-ws s (inc i)))
            out (assoc out k v)
            i (skip-ws s i)]
        (if (= (nth s i) \,)
          (recur (skip-ws s (inc i)) out)
          [out (inc i)])))))

(defn- json-value [^String s i]
  (let [i (skip-ws s i), c (nth s i)]
    (cond
      (= c \{) (json-object s i)
      (= c \[) (json-array s i)
      (= c \") (json-string s i)
      (= c \t) [true (+ i 4)]
      (= c \f) [false (+ i 5)]
      (= c \n) [nil (+ i 4)]
      :else (json-number s i))))

(defn parse-json [text] (first (json-value text 0)))

(defn- strip-star-dot [s]
  ;; .strip().lstrip("*.")  — leading '*' and '.' chars removed
  (str/replace (str/trim s) #"^[*.]+" ""))

(defn parse-crtsh
  "Port of parse_crtsh(text, sourcing). crt.sh JSON → [domains certs]."
  ([text] (parse-crtsh text "authoritative"))
  ([text sourcing]
   (let [rows (parse-json text)]
     (reduce
      (fn [[domains certs seen] r]
        (let [cn (strip-star-dot (or (get r "common_name") ""))
              sans (->> (str/split-lines (or (get r "name_value") ""))
                        (map strip-star-dot)
                        (filter #(not= "" (str/trim %)))
                        vec)
              ;; {cn, *sans} dedup, cn first then sans in order (Python set order not testable)
              cand (distinct (cons cn sans))
              [domains seen]
              (reduce
               (fn [[domains seen] d]
                 (if (or (= "" d) (contains? seen d))
                   [domains seen]
                   (let [tld (if (str/includes? d ".") (last (str/split d #"\.")) d)]
                     [(assoc domains (str "domain." (slug d))
                             {":domain/id" (str "domain." (slug d)) ":domain/fqdn" d
                              ":domain/tld" tld ":domain/sourcing" (str ":" sourcing)})
                      (conj seen d)])))
               [domains seen]
               cand)
              sha (str (or (get r "serial_number") (get r "id") ""))
              cert {":tlscert/id" (str "cert." (slug cn) "." (if (= "" (subs sha 0 (min 8 (count sha)))) "x" (subs sha 0 (min 8 (count sha)))))
                    ":tlscert/sha256" sha
                    ":tlscert/issuer" (get r "issuer_name" "?")
                    ":tlscert/subject" cn
                    ":tlscert/san" (if (seq sans) sans [cn])
                    ":tlscert/not-before" (subs (or (get r "not_before") "") 0 (min 10 (count (or (get r "not_before") ""))))
                    ":tlscert/not-after" (subs (or (get r "not_after") "") 0 (min 10 (count (or (get r "not_after") ""))))
                    ":tlscert/ct-log" "crt.sh"
                    ":tlscert/anomaly" ":none"
                    ":tlscert/sourcing" (str ":" sourcing)}]
          [domains (conj certs cert) seen]))
      [{} [] #{}]
      rows)
     ;; final: [domains.values() certs]
     )))

(defn bridge-pdns
  "Port of bridge_pdns(records, sourcing). passive-DNS-shaped JSON → [domains pdns]."
  ([records] (bridge-pdns records "representative"))
  ([records sourcing]
   (let [[domains pdns]
         (reduce
          (fn [[domains pdns] r]
            (let [d (str/trim (str (get r "domain" "")))]
              (if (= "" d)
                [domains pdns]
                (let [did (str "domain." (slug d))
                      domains (assoc domains did
                                     {":domain/id" did ":domain/fqdn" d
                                      ":domain/tld" (if (str/includes? d ".") (last (str/split d #"\.")) d)
                                      ":domain/sourcing" (str ":" sourcing)})
                      rrtype (str/lower-case (str (get r "rrtype" "a")))
                      rrdata (or (get r "rrdata")
                                 (if (get r "value") [(get r "value")] []))
                      rec0 {":pdns/id" (str "pdns." (slug d) "." rrtype "." (slug (str (vec (take 1 rrdata)))))
                            ":pdns/domain" did ":pdns/rrtype" (str ":" rrtype)
                            ":pdns/rrdata" rrdata ":pdns/sourcing" (str ":" sourcing)}
                      rec1 (if (and (contains? #{"a" "aaaa"} rrtype) (seq rrdata))
                             (assoc rec0 ":pdns/ip" (ip-id (first rrdata)))
                             rec0)
                      rec2 (if (some? (get r "ttl"))
                             (assoc rec1 ":pdns/ttl" (long (get r "ttl")))
                             rec1)
                      rec3 (if (get r "first_seen")
                             (assoc rec2 ":pdns/first-seen-at" (get r "first_seen"))
                             rec2)
                      rec4 (if (get r "last_seen")
                             (assoc rec3 ":pdns/last-seen-at" (get r "last_seen"))
                             rec3)]
                  [domains (conj pdns rec4)]))))
          [{} []]
          records)]
     [(vec (vals domains)) pdns])))

;; NOTE: parse-crtsh above returns the raw reduce accumulator; expose a clean [domains certs].
(defn parse-crtsh-result
  "[domains-vec certs-vec] for parse-crtsh (Python returns list(domains.values()), certs)."
  ([text] (parse-crtsh-result text "authoritative"))
  ([text sourcing]
   (let [[domains certs _seen] (parse-crtsh text sourcing)]
     [(vec (vals domains)) certs])))

;; ── Cloudflare zone HTTP-scanner bridge (ADR-2607170800) ────────────────────
;; Turns per-request Cloudflare zone observations into :indicator/* :scanner IOCs.
;; The kotoba estate serves NO WordPress/Joomla/PHP/.env/.git, so any request to
;; those paths on an operator-owned zone is unambiguous hostile reconnaissance
;; (honeypot posture — the catch-all 200 keeps scanners engaged; yabai only SCORES,
;; never blocks). This is the single source of truth for the detection heuristic that
;; the live sweep (cf_sweep.cljc, G7-gated) and any offline replay both consume.

(def scanner-probe-re
  "A path that has no legitimate reason to be requested on a kotoba (SvelteKit/cljs) zone —
  WordPress/Joomla surface, secrets files, framework consoles, known-RCE probes."
  #"(?i)wp-|\.php\b|xmlrpc|\.env|/\.git|wlwmanifest|/admin|\.aws|\.docker|phpinfo|/shell|/config\.|backup|\.sql\b|jce|joomla|cgi-bin|filemanager|bypass|\.trash|/vendor/|/laravel|/telescope|/actuator|/owa/|/autodiscover|/boaform|/GponForm|/HNAP1|/manager/html|/solr/|/druid/|/geoserver|/webui|/remote/login|/\.vscode|/\.ssh|/id_rsa|/etc/passwd|\.bak\b|/setup-config|/adminer|/_profiler|/_shell|\.gitconfig|/php\.php|/pinfo|/info\.php")

(defn probe-path?
  "True when path is scanner reconnaissance (matches scanner-probe-re)."
  [path]
  (boolean (and path (re-find scanner-probe-re path))))

(defn scanner-tier
  "Confidence tier for a source IP by breadth (distinct zones) and volume (probe reqs).
  → [confidence status]. >=4 zones or >=500 req = high/confirmed; >=2 zones or >=50 = mid/
  confirmed; else weak/candidate."
  [n-zones probe]
  (cond
    (or (>= n-zones 4) (>= probe 500)) [900 ":confirmed"]
    (or (>= n-zones 2) (>= probe 50))  [820 ":confirmed"]
    :else                               [700 ":candidate"]))

(defn- ioc-ip-id [ip] (str "ioc.ip." (-> ip (str/replace "." "-") (str/replace ":" "-"))))

(defn bridge-cf-scanners
  "Aggregate normalized Cloudflare observations into :indicator/* :scanner IOC rows.
  Each obs is a map {\"ip\" \"cc\" \"path\" \"count\" \"zone\" \"day\"} (string keys, JSON-shaped
  like bridge-pdns). Only probe-path? observations contribute. Deterministic: rows sorted by
  (zones desc, probe desc, ip asc); one row per source IP. sourcing defaults :authoritative
  (first-hand on operator-owned zones)."
  ([obs] (bridge-cf-scanners obs "kotoba-cf-zones" "authoritative"))
  ([obs source sourcing]
   (let [agg (reduce
              (fn [m o]
                (let [p (get o "path")]
                  (if-not (probe-path? p)
                    m
                    (let [ip (get o "ip")
                          c  (long (or (get o "count") 1))
                          rec (or (get m ip)
                                  {:cc (get o "cc") :probe 0 :zones #{} :days #{}})]
                      (assoc m ip
                             (-> rec
                                 (update :probe + c)
                                 (update :zones conj (get o "zone"))
                                 (update :days conj (get o "day"))
                                 (assoc :cc (or (:cc rec) (get o "cc")))))))))
              {} obs)]
     (->> agg
          (map (fn [[ip r]]
                 (let [nz (count (:zones r))
                       [conf status] (scanner-tier nz (:probe r))
                       days (sort (:days r))]
                   {:ip ip :nz nz :probe (:probe r)
                    :row (array-map
                          ":indicator/id" (ioc-ip-id ip)
                          ":indicator/type" ":ip"
                          ":indicator/value" ip
                          ":indicator/category" ":scanner"
                          ":indicator/tlp" ":clear"
                          ":indicator/confidence" conf
                          ":indicator/status" status
                          ":indicator/first-seen-at" (first days)
                          ":indicator/last-seen-at" (last days)
                          ":indicator/source" source
                          ":indicator/sourcing" (str ":" sourcing))})))
          (sort-by (juxt (comp - :nz) (comp - :probe) :ip))
          (mapv :row)))))

(def ^:private merge-id-keys
  [":domain/id" ":pdns/id" ":iphist/id" ":tlscert/id"
   ":indicator/id" ":access/id" ":btobs/id"])

(defn key-of
  "Port of _key(rec): first present id key's value, else nil."
  [rec]
  (some (fn [k] (when (contains? rec k) (get rec k))) merge-id-keys))

(defn merge-rows
  "Port of the seed+bridged dedup-merge: dedup by id, seed wins (first seen)."
  [seed-rows bridged]
  (first
   (reduce
    (fn [[merged seen] rec]
      (if-not (map? rec)
        [merged seen]
        (let [k (key-of rec)]
          (if (or (nil? k) (contains? seen k))
            [merged seen]
            [(conj merged rec) (conj seen k)]))))
    [[] #{}]
    (concat seed-rows bridged))))

(defn merge-many
  "Dedup-merge many row-seqs by id, FIRST-seen wins (earlier seq = higher authority; pass seed
  first). Generalizes merge-rows for the whole data/ IOC set so every curated file flows into the
  graph analyze/autorun read (previously only merge-rows' single 'bridged' arg landed)."
  [row-seqs]
  (first
   (reduce
    (fn [[merged seen] rec]
      (if-not (map? rec)
        [merged seen]
        (let [k (key-of rec)]
          (if (or (nil? k) (contains? seen k))
            [merged seen]
            [(conj merged rec) (conj seen k)]))))
    [[] #{}]
    (apply concat row-seqs))))

;; ── live crt.sh fetch (G7-gated, public) ──────────────────────────────────────
;; crt.sh is public CT logs (no key). Offline-default: only called when --live is set.
;; The Python __main__ CLI driver + live crt.sh fetch (urllib) were intentionally omitted from
;; the initial port; this adds the minimal bb/slurp driver (ADR-2605301400 §T3 live ingest).

(defn fetch-crtsh
  "Live crt.sh CT-log pull for `domain` (G7: --live). Returns raw JSON text. crt.sh is public
  (no key). Offline-default: only called when --live is set."
  [domain]
  (slurp (str/replace crtsh "{q}" domain)))

#?(:clj
   (def ^:private here (-> *file* clojure.java.io/file .getParentFile)))
#?(:clj
   (def ^:private repo-root (.. here getParentFile getParentFile getParentFile)))
#?(:clj
   (def ^:private data-dir (clojure.java.io/file repo-root "data")))

#?(:clj
   (defn -main
     "Thin CLI driver for live CTI ingest (G7-gated). --source ct --domain example.com --live.
     Offline-default: REFUSES without --live (G7 operator gate). Pulls crt.sh CT logs for the
     domain, parses to :domain/* + :tlscert/* rows (:authoritative sourcing), and writes
     data/<domain>-ct.kotoba.edn (a curated data/*.kotoba.edn source that rebuild-merged!
     folds into passive-dns.merged on the next autorun/rebuild cycle)."
     [& args]
     (let [argv (vec args)
           live? (some #{"--live"} argv)
           argmap (apply hash-map (remove #{"--live"} argv))
           source (get argmap "--source")
           domain (get argmap "--domain")]
       (when-not live?
         (println "REFUSED: --live not set (G7 operator gate, offline-default).")
         (System/exit 1))
       (when (or (nil? source) (nil? domain))
         (println "usage: -main --source ct --domain <fqdn> --live")
         (System/exit 1))
       (cond
         (= source "ct")
         (let [raw (fetch-crtsh domain)
               [domains certs] (parse-crtsh-result raw "authoritative")
               rows (concat domains certs)
               header [";; yabai — kotoba EAVT: crt.sh CT-log observations (live pull)"
                       (str ";; Generated by methods/ingest.cljc -main --source ct --domain "
                            domain " --live (G7-gated). crt.sh is public. TLP:CLEAR.")
                       ";; DO NOT EDIT BY HAND — re-run: bb ... ingest.cljc --source ct --domain <fqdn> --live"]
               out-file (clojure.java.io/file data-dir (str (slug domain) "-ct.kotoba.edn"))]
           (clojure.java.io/make-parents out-file)
           (spit out-file (edn/to-edn rows header))
           (println (pr-str {:source "ct" :domain domain
                             :domains (count domains) :certs (count certs)
                             :written (.getName out-file)}))
           (shutdown-agents))
         :else
         (do (println (str "unknown source: " source)) (System/exit 1))))))
