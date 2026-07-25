(ns yabai.methods.kotoba
  "kotoba.py — yabai kotoba Datom-log writer (local, content-addressed).
  1:1 Clojure port of `methods/kotoba.py` (ADR-2605301400 §T3 + 2605262130 + 2605312345).

  The local, autonomous-loop write path: a self-driving heartbeat appends content-addressed
  transactions to a local append-only EDN log with NO external I/O.

  G6/G10 (constitutional) is enforced HERE: every :access/* record MUST carry
  :cti.attr/encrypted true. assert-access-encrypted RAISES (PlaintextAccessError) before any
  persist if a plaintext access record is present.

  EAVT = [op entity attribute value]; op is :db/add only (append-only). Deterministic: the
  caller supplies tx_id + as_of.

  Self-contained: sha-256 + canonical-json inlined (no external deps), reusing only the sibling
  yabai.methods.yabai-edn reader/serializer. House style: ':…' keyword strings stay strings;
  file I/O only behind #?(:clj …). The Python `__main__` demo is omitted."
  (:require [clojure.string :as str]
            [yabai.methods.yabai-edn :as edn]))

(def id-keys [":domain/id" ":pdns/id" ":iphist/id" ":tlscert/id" ":indicator/id" ":access/id"])

;; PlaintextAccessError — Python subclasses ValueError. We carry the marker in ex-data.
(defn- plaintext-access-error [msg]
  (ex-info msg {::plaintext-access-error true}))

(defn plaintext-access-error?
  "True if ex is the G6/G10 PlaintextAccessError (for test parity with except PlaintextAccessError)."
  [ex]
  (boolean (::plaintext-access-error (ex-data ex))))

(defn assert-access-encrypted
  "G6/G10: REFUSE to proceed if any access-audit record is plaintext."
  [rows]
  (let [bad (->> rows
                 (filter #(and (map? %)
                               (contains? % ":access/id")
                               (not= true (get % ":cti.attr/encrypted"))))
                 (mapv #(get % ":access/id")))]
    (when (seq bad)
      (throw (plaintext-access-error
              (str (count bad) " access-audit record(s) lack :cti.attr/encrypted true (G6/G10): "
                   (pr-str bad) ". "
                   "Encrypt accessor PII into a com.etzhayyim.encrypted.* envelope first."))))))

(defn- add
  "One append-only EAVT assertion: [:db/add <entity> <attr> <value>]."
  [entity attr value]
  [":db/add" entity attr value])

(defn- first-id [r]
  (some (fn [k] (when (contains? r k) (get r k))) id-keys))

(defn graph-datoms
  "Flatten the merged CTI graph into append-only EAVT assertions. Enforces G6/G10 first."
  [rows]
  (assert-access-encrypted rows)
  (reduce
   (fn [out r]
     (if-not (map? r)
       out
       (let [e (first-id r)]
         (if (nil? e)
           out
           (reduce
            (fn [out [k v]]
              (if (contains? (set id-keys) k)
                out
                (reduce (fn [out item] (conj out (add e k item)))
                        out
                        (if (sequential? v) v [v]))))
            out
            r)))))
   []
   rows))

;; ── ordered (insertion-tracking) accumulator for the derived sorts (parity w/ analyze) ──
(defn- omap-items [m]
  (if-let [order (::order (meta m))]
    (map (fn [k] [k (get m k)]) order)
    (seq m)))

(defn- sort-desc-by-val [m]
  (sort-by (fn [[_k v]] (- v)) (omap-items m)))

(defn- lstrip-colon [s] (str/replace (str s) #"^:+" ""))

(defn derived-datoms
  "Flatten the analyzer's derived :cti/* signals into EAVT assertions, each flagged
  :cti/derived true. `concentration` is the map returned by yabai.methods.analyze/analyze."
  ([concentration] (derived-datoms concentration "cti"))
  ([concentration prefix]
   (let [a concentration
         out (transient [])
         add! (fn [d] (conj! out d))]
     (doseq [[i [dom nips ttl]] (map-indexed vector (get a "fast_flux"))]
       (let [e (str prefix "-fastflux-" i)]
         (add! (add e ":cti/fast-flux-domain" dom))
         (add! (add e ":cti/distinct-ips" nips))
         (add! (add e ":cti/ttl" ttl))
         (add! (add e ":cti/derived" true))))
     (doseq [[pt n] (sort-desc-by-val (get a "ptype_load"))]
       (let [e (str prefix "-hosting-" (lstrip-colon pt))]
         (add! (add e ":cti/hosting-concentration" pt))
         (add! (add e ":cti/observations" n))
         (add! (add e ":cti/derived" true))))
     (doseq [[tlp n] (sort-desc-by-val (get a "tlp_load"))]
       (let [e (str prefix "-tlp-" (lstrip-colon tlp))]
         (add! (add e ":cti/ioc-tlp-load" tlp))
         (add! (add e ":cti/indicators" n))
         (add! (add e ":cti/derived" true))))
     (doseq [[cat n] (sort-desc-by-val (get a "cat_load"))]
       (let [e (str prefix "-cat-" (lstrip-colon cat))]
         (add! (add e ":cti/ioc-category-load" cat))
         (add! (add e ":cti/indicators" n))
         (add! (add e ":cti/derived" true))))
     (doseq [[ip n] (get a "ip_movement")]
       (let [e (str prefix "-ipmove-" (lstrip-colon ip))]
         (add! (add e ":cti/ip-movement" ip))
         (add! (add e ":cti/history-observations" n))
         (add! (add e ":cti/derived" true))))
     (doseq [[i [subj nsan anom]] (map-indexed vector (get a "cert_pivot"))]
       (let [e (str prefix "-certpivot-" i)]
         (add! (add e ":cti/cert-pivot" subj))
         (add! (add e ":cti/san-count" nsan))
         (add! (add e ":cti/anomaly" anom))
         (add! (add e ":cti/derived" true))))
     (let [e (str prefix "-access-audit")]
       (add! (add e ":cti/access-audit-total" (get a "access_total")))
       (add! (add e ":cti/access-encrypted" (get a "access_encrypted")))
       (add! (add e ":cti/plaintext-violations" (get a "plaintext_violations")))
       (add! (add e ":cti/derived" true)))
     (persistent! out))))

;; ── sha-256 ──────────────────────────────────────────────────────────────────
(defn- sha256-hex
  ^String [^String s]
  #?(:clj (let [d (.digest (java.security.MessageDigest/getInstance "SHA-256") (.getBytes s "UTF-8"))]
            (apply str (map #(format "%02x" (bit-and % 0xff)) d)))
     :default (throw (ex-info "bind a sha-256 impl on this host" {}))))

;; ── canonical JSON (json.dumps sort_keys=True, separators=(",",":"), ensure_ascii=False) ──
(defn- json-escape-utf8 ^String [^String s]
  (str/escape s {\" "\\\"" \\ "\\\\"
                 \backspace "\\b" \tab "\\t" \newline "\\n" \formfeed "\\f" \return "\\r"}))

(defn- canonical-json ^String [v]
  (cond
    (string? v)     (str "\"" (json-escape-utf8 v) "\"")
    (boolean? v)    (if v "true" "false")
    (nil? v)        "null"
    (integer? v)    (str v)
    (number? v)     (str v)
    (map? v)        (str "{" (str/join "," (map (fn [k] (str "\"" (json-escape-utf8 (str k)) "\":"
                                                             (canonical-json (get v k))))
                                                (sort (keys v)))) "}")
    (sequential? v) (str "[" (str/join "," (map canonical-json v)) "]")
    :else (throw (ex-info "canonical-json: unsupported value" {:value v}))))

(defn- canonical
  "json.dumps({\"prev\": prev_cid, \"datoms\": datoms}, sort_keys=True, ...) → bytes (string here)."
  [datoms prev-cid]
  (canonical-json {"prev" prev-cid "datoms" datoms}))

(defn tx-cid
  "Content address of a transaction = sha256 over (prev_cid, datoms) → a commit-DAG."
  ([datoms] (tx-cid datoms ""))
  ([datoms prev-cid]
   (str "b" (sha256-hex (canonical datoms prev-cid)))))

(defn make-tx
  "Build a content-addressed transaction (caller supplies tx_id + as_of — no wall clock)."
  [datoms & {:keys [tx-id as-of prev-cid] :or {prev-cid ""}}]
  {":tx/id" tx-id
   ":tx/as-of" as-of
   ":tx/prev" prev-cid
   ":tx/cid" (tx-cid datoms prev-cid)
   ":tx/count" (count datoms)
   ":tx/datoms" datoms})

(defn- tx-to-edn
  "Serialize one transaction as a single-line EDN map (reuses yabai-edn/edn-val)."
  [tx]
  (let [datoms (str/join " " (map (fn [d] (str "[" (str/join " " (map edn/edn-val d)) "]"))
                                  (get tx ":tx/datoms")))]
    (str "{:tx/id " (get tx ":tx/id") " :tx/as-of " (get tx ":tx/as-of") " "
         ":tx/prev " (edn/edn-val (get tx ":tx/prev")) " :tx/cid " (edn/edn-val (get tx ":tx/cid")) " "
         ":tx/count " (get tx ":tx/count") " :tx/datoms [" datoms "]}")))

#?(:clj
   (defn append-tx
     "Append ONE transaction to the append-only log (never rewrites). Returns the tx CID."
     [tx log-path]
     (let [f (clojure.java.io/file (str log-path))]
       (.mkdirs (.getParentFile f))
       (when-not (.exists f)
         (spit f (str ";; yabai kotoba Datom log — append-only EAVT transactions "
                      "(content-addressed DAG; G6/G10: no plaintext :access PII). "
                      "DO NOT hand-edit. ADR-2605301400 §T3.\n")))
       (spit f (str (tx-to-edn tx) "\n") :append true)
       (get tx ":tx/cid"))))

#?(:clj
   (defn read-log
     "Read the log back as a list of transaction maps (uses the shared yabai-edn reader)."
     [log-path]
     (let [f (clojure.java.io/file (str log-path))]
       (if-not (.exists f)
         []
         (->> (str/split-lines (slurp f))
              (map str/trim)
              (remove (fn [line] (or (= "" line) (str/starts-with? line ";"))))
              (mapv (fn [line] (edn/read-edn line))))))))

#?(:clj
   (defn head-cid
     "The content-addressed HEAD = the last transaction's CID."
     [log-path]
     (let [txs (read-log log-path)]
       (if (seq txs) (get (last txs) ":tx/cid") ""))))

#?(:clj
   (defn verify-chain
     "Recompute every CID from its datoms + prev; verify the DAG is intact. {ok, length, broken_at}."
     [log-path]
     (let [txs (read-log log-path)]
       (loop [i 0, prev "", remaining txs]
         (if (empty? remaining)
           {"ok" true "length" (count txs) "broken_at" -1}
           (let [tx (first remaining)
                 expect (tx-cid (get tx ":tx/datoms" []) prev)]
             (if (or (not= (get tx ":tx/cid") expect) (not= (get tx ":tx/prev") prev))
               {"ok" false "length" (count txs) "broken_at" i}
               (recur (inc i) (get tx ":tx/cid") (rest remaining)))))))))
