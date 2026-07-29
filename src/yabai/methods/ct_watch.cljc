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
   (defn- sh*
     "Run argv, return {:out :err :exit}. Use this whenever SUCCESS matters — git reports
     rejections, auth failures and 'fatal:' on stderr with a non-zero exit, so judging a
     subprocess by grepping its stdout silently calls every failure a success. Measured
     2026-07-28: a non-fast-forward `git push` was reported as {:pushed true} and the tick
     exited 0 with the findings sitting in a local commit only."
     ([argv] (sh* argv nil))
     ([argv dir]
      (let [pb (ProcessBuilder. ^java.util.List argv)
            _ (when dir (.directory pb (clojure.java.io/file dir)))
            p (.start pb)
            out (slurp (.getInputStream p))
            err (slurp (.getErrorStream p))]
        {:out out :err err :exit (.waitFor p)}))))

#?(:clj
   (defn- sh
     "Run argv, return stdout. For calls whose OUTPUT is the point (dig, curl, git rev-parse);
     if the outcome is the point, use sh*. Subprocess discipline from cf_sweep (bb/SCI
     restricts HttpURLConnection output streams, and ships no JNDI for DNS TXT)."
     [argv]
     (:out (sh* argv))))

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
     ;; The guard exists to stop a spin when a log stops advancing, so it has to scale with
     ;; the request instead of being a constant. At 64 it was a SILENT CEILING: argon2026h2
     ;; returns ~32 entries per response, so 64 requests capped a tick at ~2,019 entries no
     ;; matter what --entries said — asking for 4096 measurably returned 2019. That cap is
     ;; why the watch consumed 1,998 entries/hour while the heads advanced by millions, and
     ;; nothing reported it, because from the outside a satisfied budget and an exhausted
     ;; guard look identical. Budget for the smallest batch a log may return (16) plus slack.
     [log-url start n]
     (let [max-requests (+ 32 (quot n 16))]
       (loop [at start, names (transient []), guard 0]
         (let [want (min 256 (- (+ start n) at))]
           (if (or (<= want 0) (>= guard max-requests))
             {:names (persistent! names) :consumed (- at start) :next at
              ;; Say which limit stopped the loop. A tick that stops because it ran out of
              ;; requests is not the same event as one that finished its budget.
              :stopped (cond (<= want 0) :budget
                             (>= guard max-requests) :request-cap
                             :else :log-stalled)}
             (let [es (get-entries! log-url at (+ at want -1))]
               (if (empty? es)
                 {:names (persistent! names) :consumed (- at start) :next at :stopped :log-stalled}
                 (recur (+ at (count es))
                        (reduce (fn [acc e] (reduce conj! acc (or (entry->names e) []))) names es)
                        (inc guard))))))))))

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

#?(:clj (def ^:private state-lock (Object.)))

#?(:clj
   (defn update-state!
     "Read-modify-write the cursor file atomically, returning the new state.

     Shards run CONCURRENTLY, and each one owns only its own key. Reading the state once
     at the top of a tick and writing the whole map back at the end is safe only while
     ticks are serial: run six at once and the last writer restores five stale cursors,
     silently rewinding those shards to where they were an hour ago. Re-reading inside the
     lock means each shard merges into whatever its siblings have already committed."
     [f]
     (locking state-lock
       (let [next (f (read-state))]
         (write-state! next)
         next))))

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
           {:keys [names consumed next stopped]} (collect-names! log-url cursor entries)
           candidates (interesting-names names)
           obs (enrich! candidates observed)
           ;; ONE cumulative observation file per log, not one per cursor. A resident tick that
           ;; wrote `ct-watch-<log>-<cursor>.json` and scored only that file erased the previous
           ;; tick's findings from the merged graph on the next run — and would have left 8760
           ;; files a year behind. Folding instead means (a) nothing is lost, (b) co-hosting gets
           ;; STRONGER over time as more domains accumulate on the same address, and (c) the git
           ;; history of this one file is the growth log (the toshokan pattern).
           out-file (clojure.java.io/file data-dir "ingest" (str "ct-watch-" log ".json"))
           ;; Re-apply the prefilter to what is already on disk. The roster changes over
           ;; time — adding a brand's own infrastructure to :home retroactively exempts
           ;; observations that were admitted before. Leaving them would inflate
           ;; observation-volume (a maturity dimension) with names that can never become a
           ;; claim, which is gaming the metric with junk. Measured 2026-07-28: 921 of the
           ;; accumulated CT observations were `*.amazonaws.com` and friends.
           prior (->> (if (.exists out-file)
                        (or (ingest/parse-json (slurp out-file)) [])
                        [])
                      (filter #(some? (phish/lexical-hit (get % "domain"))))
                      vec)
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
       ;; `:history` exists so the maturity score can compute a RATE without reading a
       ;; clock. Each tick appends (epoch-ms, head, cursor); two points are enough to
       ;; divide issuance by consumption. `:last` alone cannot support this — it carries a
       ;; date, and a date cannot express "the head moved 2.3M entries while we took 333".
       ;; Bounded at 96 samples (~4 days hourly): long enough to survive a quiet night,
       ;; short enough that the state file stays a cursor rather than a time series.
       (update-state! (fn [state]
                        (-> state
                         (assoc-in [:cursors log] next)
                         (assoc-in [:last log] {:at observed :tree-size size
                                                :consumed consumed :names (count names)
                                                :candidates (count candidates)})
                         (update-in [:history log]
                                    (fn [h]
                                      (->> (conj (vec h) {:t (System/currentTimeMillis)
                                                          :head size :cursor next})
                                           (take-last 96)
                                           vec))))))
       {:log log :tree-size size :from cursor :to next :entries-consumed consumed
        :stopped stopped :behind (- size next)
        :names (count names) :distinct-names (count (distinct (keep normalize-fqdn names)))
        :candidates (count candidates)
        :candidate-names candidates
        :resolved (count (filter #(get % "ip") obs))
        :fresh fresh :cumulative (count folded)
        :written (when (seq folded) (.getName out-file))})))

#?(:clj
   (defn mirror-to-radicle!
     "Mirror the tick's commits onto the radicle plane, if this actor declares a :rad-rid.

     GitHub and radicle are two independent copies, and a `git push origin` reaches only the
     first. That is not hypothetical drift: on 2026-07-28 the radicle copy of this repo was
     seven commits behind at cebe2b4 — registered in the west manifest, node running, and
     receiving nothing — purely because the checkout had no rad remote. The remote is created
     here when missing so a fresh clone grows both planes without a manual setup step.

     Never fatal: radicle being unreachable must not fail a tick whose findings already
     reached GitHub. The outcome is reported, not swallowed."
     []
     (try
       (let [actor-file (clojure.java.io/file repo-root "actor.edn")
             rid (when (.exists actor-file)
                   (:rad-rid (clojure.edn/read-string (slurp actor-file))))]
         (if-not rid
           {:configured false}
           (let [bare (str/replace rid #"^rad:" "")
                 remotes (sh ["git" "-C" (str repo-root) "remote"])]
             (when-not (some #{"rad"} (str/split-lines remotes))
               (sh ["git" "-C" (str repo-root) "remote" "add" "rad" (str "rad://" bare)])
               (when-let [nid (not-empty (str/trim (sh ["rad" "self" "--nid"])))]
                 (sh ["git" "-C" (str repo-root) "remote" "set-url" "--push" "rad"
                      (str "rad://" bare "/" nid)])))
             (let [r (sh* ["git" "-C" (str repo-root) "push" "rad" "HEAD:main"])]
               {:configured true
                :pushed (zero? (:exit r))
                :note (str/trim (str (:out r) (:err r)))}))))
       (catch Exception e {:configured true :pushed false :note (str "rad mirror failed: "
                                                                    (.getMessage e))}))))

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
               push (sh* ["git" "-C" (str repo-root) "push" "origin" "HEAD:main"])]
           {:committed true
            :pushed (zero? (:exit push))
            :rad (mirror-to-radicle!)
            :note (str/trim (str (:out push) (:err push)))})))))

;; ── fleet fan-out ───────────────────────────────────────────────────────────
(def remote-src-dir
  "Where the collector is staged on a fleet node. Not the repo: fleet nodes have no
  checkout, and the previous `--plan` emitted `cd <local repo-root> && bb -cp src`, a path
  that exists on the operator's laptop and nowhere else — which is why that batch had never
  been executed once in the life of this actor. It was a preview of a doomed command."
  "/tmp/yabai-src")

(defn fanout-batch
  "murakumo task specs covering `slices-per-log` slices of `per-slice` entries on each log,
  taken AHEAD of each stored cursor so the fleet widens coverage instead of re-reading what
  the resident tick already consumed. Pure: builds the batch, runs nothing.

  Each task returns only what survives the PURE prefilter. That is the whole economy of
  this design — measured 2026-07-29, 26,000 entries yielded 55,708 SAN names remotely and
  sent 173 names home. The firehose never crosses the network; DNS enrichment and scoring
  stay local, where the corpus is."
  [state logs slices-per-log per-slice]
  {:tasks
   (vec (for [log (sort logs)
              i (range slices-per-log)
              :let [cur (get-in state [:cursors log] 0)
                    ;; skip the band the resident tick is working through
                    start (+ cur (* per-slice (inc slices-per-log)) (* i per-slice))]]
          {:id (str "ct-" log "-" i)
           :cmd (str "bb -cp " remote-src-dir " -e "
                     "\"(require (quote [yabai.methods.ct-watch :as w])) "
                     "(let [u (get w/ct-logs \\\"" log "\\\") "
                     "r (w/collect-names! u " start " " per-slice ")] "
                     "(prn {:log \\\"" log "\\\" :start " start
                     " :consumed (:consumed r) :names (count (:names r)) "
                     ":candidates (w/interesting-names (:names r))}))\"")}))})

#?(:clj
   (defn fanout!
     "Stage the collector on the fleet, run the batch, fold the harvest into the corpus.

     Politeness is a design constraint, not a tuning knob: `--slots 1` keeps ONE in-flight
     request per node. CT logs are public infrastructure run as a public good, and the
     temptation here is to treat them as a throughput problem. Raising fleet-wide request
     rate against Google/Cloudflare endpoints is an operator's decision, so it is spelled
     out rather than buried in a default.

     Partial failure is normal and is reported, never smoothed over: nodes go unreachable
     and tools go missing. The run succeeds on whatever answered."
     [{:keys [logs slices-per-log per-slice nodes score? commit?]}]
     ;; Resolve murakumo by finding its entrypoint, not by assuming a directory layout.
     ;; Deriving it from repo-root's grandparent works in the west checkout and produces a
     ;; path under the scratchpad when this runs from a worktree — which is where it was
     ;; first tried. A wrong path must fail loudly with the candidates listed, never leave
     ;; the caller guessing why no task was placed.
     (let [candidates (keep identity
                            [(System/getenv "MURAKUMO_ROOT")
                             (str (.getParentFile (.getParentFile repo-root))
                                  "/kotoba-lang/murakumo")
                             (str (System/getProperty "user.home")
                                  "/github/com-junkawasaki/orgs/kotoba-lang/murakumo")])
           murakumo (or (first (filter #(.exists (clojure.java.io/file % "scripts/run-task.cljs"))
                                       candidates))
                        (throw (ex-info "murakumo entrypoint not found — set MURAKUMO_ROOT"
                                        {:tried (vec candidates)})))
           nodes (or (seq nodes)
                     ;; default to whatever the fleet probe can actually reach
                     (->> (:out (sh* ["nbb" (str murakumo "/scripts/run-task.cljs")
                                      "task" "probe" "--format" "edn"]))
                          (re-seq #":node\s+\"([a-z0-9-]+)\"[^}]*?:ssh\s+:up")
                          (map second) distinct))
           batch (fanout-batch (read-state) logs slices-per-log per-slice)
           batch-file (str (java.io.File/createTempFile "ct-fanout" ".edn"))
           staged (doall
                   (pmap (fn [n]
                           [n (zero? (:exit (sh* ["rsync" "-az" "--delete"
                                                  (str repo-root "/src/")
                                                  (str n ":" remote-src-dir "/")])))])
                         nodes))
           ready (mapv first (filter second staged))]
       (spit batch-file (pr-str batch))
       (if (empty? ready)
         {:ok false :note "no node could be staged" :staged staged}
         ;; cwd MUST be the murakumo root: `task run` resolves --fleet fleet.edn and its
         ;; ledger relative to cwd, so invoking it from here silently placed nothing. The
         ;; first version of this reported {:ok true, :attempts 0} — a fan-out that ran no
         ;; tasks at all, described as a success, which is the exact defect this file has
         ;; been chasing all day.
         (let [r (sh* ["nbb" "scripts/run-task.cljs" "task" "run"
                       "--tasks" batch-file "--nodes" (str/join "," ready)
                       "--slots" "1" "--timeout-ms" "300000" "--format" "edn"]
                      murakumo)
               results (try (:run/results (clojure.edn/read-string (:out r))) (catch Exception _ nil))
               ok (filter #(zero? (or (:exit %) 1)) results)
               parsed (keep (fn [t] (try (clojure.edn/read-string (str/trim (str (:stdout t))))
                                         (catch Exception _ nil)))
                            ok)
               cands (vec (sort (distinct (mapcat :candidates parsed))))
               ;; A batch that placed nothing is a FAILURE, however cleanly it returned.
               ;; Reporting :ok on zero attempts would make a broken fleet path
               ;; indistinguishable from a quiet one, and the murakumo stderr is the only
               ;; thing that explains which — so it travels with the verdict.
               summary {:ok (pos? (count ok))
                        :murakumo-exit (:exit r)
                        :murakumo-err (when (empty? ok)
                                        (str/trim (str (:err r) (:out r))))
                        :nodes-staged (count ready)
                        :nodes-failed (mapv first (remove second staged))
                        :tasks (count (:tasks batch))
                        :attempts (count results)
                        :succeeded (count ok)
                        :failed (- (count results) (count ok))
                        :entries (reduce + 0 (keep :consumed parsed))
                        :names (reduce + 0 (keep :names parsed))
                        :candidates cands
                        :distinct-candidates (count cands)}]
           (if-not (and score? (seq cands))
             summary
             (let [observed (str (java.time.LocalDate/now java.time.ZoneOffset/UTC))
                   obs (enrich! cands observed)
                   out-name (str "ct-fanout-" (str/replace observed "-" ""))
                   in-file (clojure.java.io/file data-dir "ingest" (str out-name ".json"))]
               (clojure.java.io/make-parents in-file)
               (spit in-file (str "[\n"
                                  (str/join ",\n"
                                            (map (fn [o]
                                                   (str " {" (str/join ", "
                                                                       (map (fn [[k v]]
                                                                              (str (edn/edn-str k) ": "
                                                                                   (if (number? v) v (edn/edn-str v))))
                                                                            o)) "}"))
                                                 obs))
                                  "\n]\n"))
               (let [scored (phish/score-file! in-file out-name "ct-fanout")]
                 (merge summary
                        {:resolved (count (filter #(get % "ip") obs))
                         :scored scored}
                        (when commit?
                          {:git (commit-and-push!
                                 {:log (str "fanout:" (str/join "+" (sort logs)))
                                  :from 0 :to 0
                                  :candidates (count cands)
                                  :fresh (:confirmed scored)
                                  :cumulative (:observations scored)})}))))))))))

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
           ;; `--log all` or a comma list tails several shards in ONE tick, splitting the
           ;; entry budget between them. Rotating one shard per tick would sample each only
           ;; every Nth hour; splitting keeps every cursor moving on every tick for the same
           ;; total work, and log-coverage is a maturity dimension precisely because one
           ;; shard is not a view of worldwide issuance (measured 2026-07-28: argon2026h2
           ;; 2.21e9 entries, but nimbus2026 alone holds 5.68e9 more).
           logs (cond
                  (= "all" log) (vec (sort (keys ct-logs)))
                  (str/includes? log ",") (vec (str/split log #","))
                  :else [log])
           _ (doseq [l logs]
               (when-not (ct-logs l)
                 (throw (ex-info "unknown CT log" {:log l :known (sort (keys ct-logs))}))))
           entries (Long/parseLong (or (opt "--entries") "2000"))
           per-log (max 1 (quot entries (count logs)))]
       (cond
         (opt "--plan")
         (do (println (pr-str (fanout-batch (read-state) logs
                                            (Long/parseLong (opt "--plan"))
                                            per-log)))
             0)

         (opt "--fanout")
         (let [n (Long/parseLong (opt "--fanout"))
               nodes (some-> (opt "--nodes") (str/split #",") vec)
               r (fanout! {:logs logs :slices-per-log n :per-slice per-log :nodes nodes
                           :score? (some #{"--score"} argv)
                           :commit? (some #{"--commit"} argv)})]
           (println (pr-str (dissoc r :candidates)))
           (if (:ok r) 0 (System/exit 1)))

         ;; System/exit, not a return value: launchd and `tamaki exec` read the exit code,
         ;; and `bb -m` discards whatever -main returns.
         (not live?)
         (do (println "REFUSED: --live not set (G7 operator gate, offline-default).")
             (System/exit 1))

         :else
         (let [results
               ;; Shards run CONCURRENTLY. They are independent cursors on six endpoints
               ;; across two operators, and a serial loop made the tick's wall-clock the
               ;; SUM of six network-bound fetches — six times longer for no reason, which
               ;; is the second reason (after the request cap) the watch consumed so little.
               ;; Politeness is preserved: concurrency is ACROSS logs, never within one, so
               ;; no single operator sees more than one in-flight request from this tick.
               ;; `update-state!` is what makes this safe for the shared cursor file.
               (doall
                (pmap
                 (fn [l]
                  ;; One shard failing must not lose the shards that already succeeded —
                  ;; CT logs return 5xx often enough that an all-or-nothing tick would
                  ;; frequently record nothing at all.
                  (try
                    (let [r (tick! :log l :entries per-log
                                   :start (when (= 1 (count logs))
                                            (some-> (opt "--start") Long/parseLong)))]
                      (println (pr-str (dissoc r :candidate-names)))
                      (when (seq (:candidate-names r))
                        (println (str "  candidates: " (str/join " " (:candidate-names r)))))
                      r)
                    (catch Exception e
                      (binding [*out* *err*]
                        (println (str "  shard " l " FAILED: " (.getMessage e))))
                      {:log l :failed (.getMessage e)})))
                 logs))
               r (first results)]
           ;; Score each shard's CUMULATIVE file, not just this tick's additions: co-hosting
           ;; is a property of the whole observation set, so a domain seen days ago can be
           ;; corroborated by one seen now.
           (when (some #{"--score"} argv)
             (doseq [{:keys [log written]} (filter :written results)]
               (let [in (clojure.java.io/file data-dir "ingest" written)
                     scored (phish/score-file! in (str "ct-watch-" log)
                                               (str "yabai-ct-watch-" log))]
                 (println (pr-str (assoc (select-keys scored [:observations :confirmed
                                                              :candidate :unscored :rows])
                                         :log log)))))
             (require 'yabai.methods.cf-sweep)
             (println (pr-str ((resolve 'yabai.methods.cf-sweep/rebuild-merged!)))))
           (when (some #{"--commit"} argv)
             (let [ok (filter :written results)
                   g (commit-and-push!
                      {:log (str/join "+" (map :log ok))
                       :from (apply min (conj (keep :from ok) 0))
                       :to (apply max (conj (keep :to ok) 0))
                       :candidates (reduce + 0 (keep :candidates ok))
                       :fresh (reduce + 0 (keep :fresh ok))
                       :cumulative (reduce + 0 (keep :cumulative ok))})]
               (println (pr-str g))
               (when (and (:committed g) (not (:pushed g)))
                 (println "push FAILED — the tick's findings are committed locally only.")
                 (System/exit 1))))
           0)))))
