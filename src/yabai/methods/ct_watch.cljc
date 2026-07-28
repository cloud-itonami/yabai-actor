(ns yabai.methods.ct-watch
  "ct_watch — worldwide domain SUPPLY for the ADR-0003 phishing scorer (ADR-0004).

  ADR-0003 shipped the judgement but left the population gap open: the scorer could only
  ever see the one committed 2026-04-19 corpus and single-domain `ingest --live --domain`
  pulls. This closes it by tailing **Certificate Transparency logs**, which observe every
  publicly-trusted certificate issued anywhere on earth.

  Why CT logs and not crt.sh: crt.sh is the right tool for ONE known domain (ADR-0002) but
  cannot serve a brand-wide population query — measured 2026-07-28, `?q=%25mastercard%25`
  returns 502/404 and even `?q=mastercard.com` returns 503, while `?q=etzhayyim.com` takes
  36s. The logs themselves have no such problem: `get-sth` + `get-entries` are the machine
  interface CT was designed for, need no key, and are served by Google / Cloudflare /
  DigiCert / Sectigo directly.

  Pipeline per tick: cursor → get-entries → X.509 SAN names → **cheap pure lexical
  prefilter** → DNS A + Team Cymru ASN only for survivors → observation JSON in the exact
  shape phish-infra already consumes → score → merged graph.

  The prefilter ordering is the whole trick. CT is a firehose (Argon2026h2 alone was
  2.20e9 entries on 2026-07-28); resolving every name would be both impossible and rude.
  `phish-infra/lexical-hit` is pure and costs nothing, so it runs first and only a handful
  of names per slice ever reach the network.

  HONEST SCOPE: one tick samples a SLICE of one log. It is a sampling watch, not complete
  worldwide coverage — see `plan-slices` / `murakumo task run` for the fan-out that widens
  it. Absence from this corpus means `not sampled`, never `not phishing`.

  GATE-G7: live network is operator-gated (`--live`), matching ingest / cf_sweep.

  House style: pure fns portable and tested; network + file I/O behind #?(:clj …); HTTP and
  DNS go through curl / dig subprocesses, the same discipline cf_sweep uses (bb ships no
  JNDI, so `javax.naming` is not available for the Cymru TXT lookup)."
  (:require [clojure.string :as str]
            [yabai.methods.ingest :as ingest]
            [yabai.methods.phish-infra :as phish]
            [yabai.methods.yabai-edn :as edn]))

;; Usable CT logs (https://www.gstatic.com/ct/log_list/v3/log_list.json, checked 2026-07-28).
;; Shards are time-boxed by design, so this list is expected to age; `--log-url` overrides it
;; and a missing shard fails loudly rather than silently tailing nothing.
(def ct-logs
  {"argon2026h2" "https://ct.googleapis.com/logs/us1/argon2026h2/"
   "argon2027h1" "https://ct.googleapis.com/logs/us1/argon2027h1/"
   "xenon2026h2" "https://ct.googleapis.com/logs/eu1/xenon2026h2/"
   "xenon2027h1" "https://ct.googleapis.com/logs/eu1/xenon2027h1/"
   "nimbus2026"  "https://ct.cloudflare.com/logs/nimbus2026/"
   "nimbus2027"  "https://ct.cloudflare.com/logs/nimbus2027/"})

(def default-log "argon2026h2")

;; ── MerkleTreeLeaf parsing (RFC 6962 §3.4) ──────────────────────────────────
;; version(1) leaf_type(1) timestamp(8) entry_type(2), then either
;;   entry_type 0 (x509_entry)  : ASN.1Cert = uint24 length + DER
;;   entry_type 1 (precert)     : issuer_key_hash(32) + TBS — the FULL precert that carries
;;                                the SANs lives in extra_data, again uint24 + DER.

(defn u24
  "Big-endian 24-bit length at `off`. Byte values arrive signed on the JVM."
  [bytes-seq off]
  (let [b (fn [i] (bit-and (int (nth bytes-seq i)) 0xff))]
    (+ (bit-shift-left (b off) 16) (bit-shift-left (b (+ off 1)) 8) (b (+ off 2)))))

(defn entry-type
  "0 = x509_entry, 1 = precert_entry."
  [bytes-seq]
  (let [b (fn [i] (bit-and (int (nth bytes-seq i)) 0xff))]
    (+ (bit-shift-left (b 10) 8) (b 11))))

(defn cert-span
  "[offset length] of the DER certificate, given the decoded leaf_input and extra_data byte
  vectors. Returns [:leaf off len] or [:extra off len], or nil for an unknown entry type."
  [leaf extra]
  (case (entry-type leaf)
    0 [:leaf 15 (u24 leaf 12)]
    1 (when (seq extra) [:extra 3 (u24 extra 0)])
    nil))

;; ── name normalization + prefilter ──────────────────────────────────────────
(defn normalize-fqdn
  "`*.Foo.EXAMPLE.com ` → `foo.example.com`. nil for anything that is not a plausible name
  (CT SANs also carry IPs and, rarely, junk)."
  [s]
  (let [n (-> (str s) str/trim str/lower-case (str/replace #"^\*\." ""))]
    (when (and (seq n)
               (str/includes? n ".")
               (re-matches #"[a-z0-9._-]+" n)
               (not (re-matches #"[0-9.]+" n)))
      n)))

(defn interesting-names
  "Names worth spending a DNS lookup on: those the ADR-0003 lexical scorer already flags.
  Pure, so it runs over the whole firehose slice before anything touches the network.
  Deduped and sorted for determinism."
  ([names] (interesting-names names phish/default-brands))
  ([names brands]
   (->> names
        (keep normalize-fqdn)
        distinct
        (filter #(some? (phish/lexical-hit % brands)))
        sort
        vec)))

(defn plan-slices
  "Split [start, end) into `n` contiguous slices — the unit of murakumo fan-out. Pure, so
  `--plan` previews the batch without touching the fleet or the logs."
  [start end n]
  (let [total (max 0 (- end start))
        n (max 1 n)
        per (quot total n)
        rem* (rem total n)]
    (when (pos? total)
      (->> (range n)
           (reduce (fn [{:keys [at out]} i]
                     (let [len (+ per (if (< i rem*) 1 0))]
                       {:at (+ at len)
                        :out (if (pos? len) (conj out {:start at :end (+ at len)}) out)}))
                   {:at start :out []})
           :out))))

;; ── #?(:clj) driver ─────────────────────────────────────────────────────────
#?(:clj (def ^:private repo-root
          (let [d (-> *file* clojure.java.io/file .getParentFile)]
            (.. d getParentFile getParentFile getParentFile))))
#?(:clj (def ^:private data-dir (clojure.java.io/file repo-root "data")))
#?(:clj (def ^:private state-file (clojure.java.io/file data-dir "ct-watch-state.edn")))

#?(:clj
   (defn- sh
     "Run argv, return stdout. Subprocess discipline from cf_sweep (bb/SCI restricts
     HttpURLConnection output streams, and ships no JNDI for DNS TXT)."
     [argv]
     (let [p (-> (ProcessBuilder. ^java.util.List argv) .start)
           out (slurp (.getInputStream p))]
       (.waitFor p)
       out)))

#?(:clj (defn- http-get [url] (sh ["curl" "-sS" "--max-time" "60" url])))

#?(:clj
   (defn get-sth!
     "Current tree size of a log (G7: live)."
     [log-url]
     (let [body (http-get (str log-url "ct/v1/get-sth"))]
       (if-let [m (re-find #"\"tree_size\"\s*:\s*(\d+)" body)]
         (Long/parseLong (second m))
         (throw (ex-info "get-sth: no tree_size" {:log log-url :body (subs body 0 (min 200 (count body)))}))))))

#?(:clj
   (defn get-entries!
     "Raw entries for [start..end] inclusive. Logs cap the batch server-side (typically 32-256)
     and simply return fewer than asked, so callers must loop on the actual count."
     [log-url start end]
     (let [body (http-get (str log-url "ct/v1/get-entries?start=" start "&end=" end))
           leaves (mapv second (re-seq #"\"leaf_input\":\"([^\"]*)\"" body))
           extras (mapv second (re-seq #"\"extra_data\":\"([^\"]*)\"" body))]
       (mapv (fn [l e] {:leaf l :extra e}) leaves (concat extras (repeat nil))))))

#?(:clj (def ^:private b64d (java.util.Base64/getDecoder)))
#?(:clj (def ^:private cert-factory (java.security.cert.CertificateFactory/getInstance "X.509")))

#?(:clj
   (defn entry->names
     "DNS SANs of one CT entry, or nil when the entry cannot be parsed. A malformed entry is
     skipped, never fatal — one bad record must not stop a tick."
     [{:keys [leaf extra]}]
     (try
       (let [lb (vec (.decode b64d ^String leaf))
             eb (when (seq extra) (vec (.decode b64d ^String extra)))]
         (when-let [[src off len] (cert-span lb eb)]
           (let [src-bytes (if (= src :leaf) lb eb)
                 der (byte-array (subvec src-bytes off (+ off len)))
                 c (.generateCertificate cert-factory (java.io.ByteArrayInputStream. der))]
             (vec (for [s (.getSubjectAlternativeNames c) :when (= 2 (first s))] (second s))))))
       (catch Exception _ nil))))

#?(:clj
   (defn collect-names!
     "Tail `n` entries from `start`, returning {:names :consumed :next}. Stops early if the log
     stops advancing so a tick can never spin."
     [log-url start n]
     (loop [at start, names (transient []), guard 0]
       (let [want (min 256 (- (+ start n) at))]
         (if (or (<= want 0) (>= guard 64))
           {:names (persistent! names) :consumed (- at start) :next at}
           (let [es (get-entries! log-url at (+ at want -1))]
             (if (empty? es)
               {:names (persistent! names) :consumed (- at start) :next at}
               (recur (+ at (count es))
                      (reduce (fn [acc e] (reduce conj! acc (or (entry->names e) []))) names es)
                      (inc guard)))))))))

#?(:clj
   (defn resolve-a!
     "IPv4 addresses for a name, or [] when it does not resolve (an unresolved impersonation
     domain is still an observation — it just gets no co-hosting corroboration)."
     [fqdn]
     (try
       (->> (java.net.InetAddress/getAllByName fqdn)
            (map #(.getHostAddress %))
            (filter #(re-matches #"[0-9.]+" %))
            vec)
       (catch Exception _ []))))

#?(:clj
   (defn cymru-asn!
     "Team Cymru origin lookup: `<reversed-ip>.origin.asn.cymru.com` TXT →
     {:asn :prefix :cc :registry}. Public, free, DNS-based. nil when unavailable."
     [ip]
     (try
       (let [rev (str/join "." (reverse (str/split ip #"\.")))
             out (str/trim (sh ["dig" "+short" "+time=5" "+tries=1" "TXT"
                                (str rev ".origin.asn.cymru.com")]))
             line (-> out (str/replace "\"" "") str/split-lines first)]
         (when (seq line)
           (let [[asn prefix cc registry] (map str/trim (str/split line #"\|"))]
             {:asn (when (re-matches #"\d+" (or asn "")) (Long/parseLong asn))
              :prefix prefix :cc cc :registry registry})))
       (catch Exception _ nil))))

#?(:clj
   (defn cymru-org!
     "AS name for an ASN (`AS<n>.asn.cymru.com` TXT). Separate lookup, cached per tick by the
     caller — there are far fewer ASNs than IPs."
     [asn]
     (try
       (let [out (str/trim (sh ["dig" "+short" "+time=5" "+tries=1" "TXT"
                                (str "AS" asn ".asn.cymru.com")]))
             line (-> out (str/replace "\"" "") str/split-lines first)]
         (when (seq line)
           (let [parts (map str/trim (str/split line #"\|"))]
             (last parts))))
       (catch Exception _ nil))))

#?(:clj
   (defn enrich!
     "DNS A + Cymru ASN for each candidate → the observation shape phish-infra consumes.
     ASN org lookups are memoised per call: a phishing cluster is by definition concentrated,
     so this is a handful of queries even for a wide slice."
     [fqdns observed]
     (let [org-cache (atom {})]
       (vec (for [d fqdns]
              (let [ips (resolve-a! d)
                    ip (first ips)
                    a (when ip (cymru-asn! ip))
                    asn (:asn a)
                    org (when asn
                          (or (get @org-cache asn)
                              (let [o (cymru-org! asn)] (swap! org-cache assoc asn o) o)))]
                (cond-> {"domain" d "observed" observed}
                  ip (assoc "ip" ip)
                  asn (assoc "asn" asn)
                  org (assoc "asn_org" org)
                  (:cc a) (assoc "asn_country" (:cc a)))))))))

#?(:clj
   (defn read-state []
     (if (.exists state-file)
       (try (clojure.edn/read-string (slurp state-file)) (catch Exception _ {}))
       {})))

#?(:clj
   (defn write-state! [s]
     (clojure.java.io/make-parents state-file)
     (spit state-file (str ";; yabai ct_watch cursor — GENERATED, do not edit by hand.\n"
                           (pr-str s) "\n"))))

#?(:clj
   (defn tick!
     "One resident tick. Returns a summary map; every count in it is measured, not assumed.

     `:start` defaults to the stored cursor for this log, and on a first run to
     `tree_size - entries` (tail the head rather than replay 2.2e9 historical entries)."
     [& {:keys [log entries observed start]
         :or {log default-log entries 2000}}]
     (let [log-url (or (ct-logs log) (throw (ex-info "unknown CT log" {:log log :known (keys ct-logs)})))
           state (read-state)
           size (get-sth! log-url)
           cursor (or start (get-in state [:cursors log]) (max 0 (- size entries)))
           cursor (min cursor size)
           observed (or observed (str (java.time.LocalDate/now java.time.ZoneOffset/UTC)))
           {:keys [names consumed next]} (collect-names! log-url cursor entries)
           candidates (interesting-names names)
           obs (enrich! candidates observed)
           ;; ONE cumulative observation file per log, not one per cursor. A resident tick that
           ;; wrote `ct-watch-<log>-<cursor>.json` and scored only that file erased the previous
           ;; tick's findings from the merged graph on the next run — and would have left 8760
           ;; files a year behind. Folding instead means (a) nothing is lost, (b) co-hosting gets
           ;; STRONGER over time as more domains accumulate on the same address, and (c) the git
           ;; history of this one file is the growth log (the toshokan pattern).
           out-file (clojure.java.io/file data-dir "ingest" (str "ct-watch-" log ".json"))
           prior (if (.exists out-file)
                   (or (ingest/parse-json (slurp out-file)) [])
                   [])
           ;; earlier observation wins, so :indicator/first-seen-at never moves forward
           folded (->> (concat prior obs)
                       (reduce (fn [m o] (if (contains? m (get o "domain")) m
                                             (assoc m (get o "domain") o)))
                               (array-map))
                       vals vec)
           fresh (- (count folded) (count prior))]
       (when (seq folded)
         (clojure.java.io/make-parents out-file)
         (spit out-file (str "[\n"
                             (str/join ",\n"
                                       (map (fn [o]
                                              (str " {"
                                                   (str/join ", "
                                                             (map (fn [[k v]]
                                                                    (str (edn/edn-str k) ": "
                                                                         (if (number? v) v (edn/edn-str v))))
                                                                  o))
                                                   "}"))
                                            folded))
                             "\n]\n")))
       (write-state! (-> state
                         (assoc-in [:cursors log] next)
                         (assoc-in [:last log] {:at observed :tree-size size
                                                :consumed consumed :names (count names)
                                                :candidates (count candidates)})))
       {:log log :tree-size size :from cursor :to next :entries-consumed consumed
        :names (count names) :distinct-names (count (distinct (keep normalize-fqdn names)))
        :candidates (count candidates)
        :candidate-names candidates
        :resolved (count (filter #(get % "ip") obs))
        :fresh fresh :cumulative (count folded)
        :written (when (seq folded) (.getName out-file))})))

#?(:clj
   (defn commit-and-push!
     "Commit exactly the files a tick owns and push. A resident tick runs inside the shared
     west checkout, so leaving the tree dirty would block `west update` and collide with
     whatever else is working there — the growth has to land in git, not sit in the worktree.
     Only the daemon's own paths are staged; anything else in the tree is left alone.
     Returns {:committed bool :pushed bool :note}."
     [summary]
     (let [paths ["data/ingest" "data/ct-watch-state.edn" "data/passive-dns.merged.kotoba.edn"]
           paths (concat paths
                         (->> (.listFiles data-dir)
                              (map #(.getName %))
                              (filter #(str/starts-with? % "ct-watch-"))
                              (map #(str "data/" %))))
           git (fn [& args] (str/trim (sh (into ["git" "-C" (str repo-root)] args))))]
       (apply git "add" "--" paths)
       (if (str/blank? (git "diff" "--cached" "--name-only"))
         {:committed false :pushed false :note "nothing to commit"}
         (let [msg (str "chore(ct-watch): " (:log summary) " "
                        (:from summary) ".." (:to summary)
                        " — " (:candidates summary) " candidates, "
                        (:fresh summary) " fresh (cumulative " (:cumulative summary) ")")
               _ (git "commit" "-q" "-m" msg)
               push (sh ["git" "-C" (str repo-root) "push" "origin" "HEAD:main"])]
           {:committed true
            :pushed (str/blank? (str/trim (or (re-find #"(?i)error|rejected|fatal" push) "")))
            :note (str/trim push)})))))

#?(:clj
   (defn -main
     "CLI. Offline-default: REFUSES without --live (G7 operator gate).

       --live                 required for any network call
       --log <key>            CT log shard (default argon2026h2)
       --entries N            entries to consume this tick (default 2000)
       --start N              explicit cursor (default: stored cursor, else tail the head)
       --score                after collecting, score + fold into the merged graph
       --plan N               PURE: print N murakumo task specs for a fan-out, run nothing"
     [& args]
     (let [argv (vec args)
           opt (fn [f] (let [i (.indexOf argv f)] (when (>= i 0) (get argv (inc i)))))
           live? (some #{"--live"} argv)
           log (or (opt "--log") default-log)
           entries (Long/parseLong (or (opt "--entries") "2000"))]
       (cond
         (opt "--plan")
         (let [n (Long/parseLong (opt "--plan"))
               log-url (ct-logs log)
               size (if live? (get-sth! log-url) (Long/parseLong (or (opt "--tree-size") "0")))
               slices (plan-slices (max 0 (- size (* n entries))) size n)]
           (println (pr-str
                     {:tasks (mapv (fn [{:keys [start end]}]
                                     {:id (str "ct-" log "-" start)
                                      :cmd (str "cd " repo-root " && bb -cp src -e "
                                                "\"(require '[yabai.methods.ct-watch :as w])"
                                                "(prn (w/tick! :log \\\"" log "\\\" :start " start
                                                " :entries " (- end start) "))\"")})
                                   slices)}))
           0)

         ;; System/exit, not a return value: launchd and `tamaki exec` read the exit code,
         ;; and `bb -m` discards whatever -main returns.
         (not live?)
         (do (println "REFUSED: --live not set (G7 operator gate, offline-default).")
             (System/exit 1))

         :else
         (let [r (tick! :log log :entries entries
                        :start (some-> (opt "--start") Long/parseLong))]
           (println (pr-str (dissoc r :candidate-names)))
           (when (seq (:candidate-names r))
             (println (str "candidates: " (str/join " " (:candidate-names r)))))
           ;; Score the CUMULATIVE file, not just this tick's additions: co-hosting is a
           ;; property of the whole observation set, so a domain seen days ago can be
           ;; corroborated by one seen now.
           (when (and (some #{"--score"} argv) (:written r))
             (let [in (clojure.java.io/file data-dir "ingest" (:written r))
                   scored (phish/score-file! in (str "ct-watch-" log)
                                             (str "yabai-ct-watch-" log))]
               (println (pr-str (select-keys scored [:observations :confirmed :candidate
                                                     :unscored :rows :written])))
               (require 'yabai.methods.cf-sweep)
               (println (pr-str ((resolve 'yabai.methods.cf-sweep/rebuild-merged!))))))
           (when (some #{"--commit"} argv)
             (let [g (commit-and-push! r)]
               (println (pr-str g))
               (when (and (:committed g) (not (:pushed g)))
                 (println "push FAILED — the tick's findings are committed locally only.")
                 (System/exit 1))))
           0)))))
