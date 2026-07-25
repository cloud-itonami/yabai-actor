(ns yabai.methods.analyze
  "analyze.py — yabai CTI / passive-DNS concentration + anomaly analyzer (ADR-2605301400 §T3).
  1:1 Clojure port of `methods/analyze.py`.

  Reads a kotoba-EDN CTI graph (classified by yabai.methods.yabai-edn/classify) and computes,
  AGGREGATE-FIRST, the DEFENSIVE threat-intel signals: fast-flux candidate domains, hosting-
  provider concentration, IOC TLP/category load, IP-movement churn, TLS cert-SAN pivots, plus a
  G6/G10 encryption self-audit. Renders out/intel-report.md + derived :cti/* datoms.

  CONSTITUTIONAL framing (yabai = risk organ, NOT enforcement): this scores DEFENSIVE risk
  context. Enforcement is the Council's; evidence is tadori's. No adherent is de-anonymised.

  House style: Python ':…' keyword strings stay strings; pure fns; file I/O only at #?(:clj)
  edges. defaultdict(int) iteration order is preserved via insertion-ordered accumulators so the
  rendered tables + derived datoms tie the Python order on ties. The Python `__main__` CLI is
  ported under #?(:clj) -main."
  (:require [clojure.string :as str]
            [yabai.methods.yabai-edn :as edn]))

(def fast-flux-ttl 300)       ; TTL ≤ this …
(def fast-flux-min-ips 3)     ; … with ≥ this many distinct A answers = fast-flux candidate

;; ── ordered (insertion-tracking) accumulator (mirror Python defaultdict iteration) ──
(defn- omap [] ^{::order []} {})

(defn- omap-inc
  "defaultdict(int)[k] += n, recording k's first-touch position in ::order."
  [m k n]
  (let [had? (contains? m k)
        m' (update m k (fnil + 0) n)]
    (if had?
      (with-meta m' (meta m))
      (with-meta m' (update (meta m) ::order conj k)))))

(defn- omap-items
  "key/value pairs in first-touch (Python defaultdict) order."
  [m]
  (if-let [order (::order (meta m))]
    (map (fn [k] [k (get m k)]) order)
    (seq m)))

(defn- sort-desc-by-val
  "sorted(items, key=lambda kv: -kv[1]) — stable, ties keep insertion order."
  [m]
  (sort-by (fn [[_k v]] (- v)) (omap-items m)))

(defn- as-int
  "Python int(x or default) coercion for ttl (string-keyed values are long/double/nil)."
  [v default]
  (cond
    (nil? v) default
    (number? v) (long v)
    :else (try (Long/parseLong (str v)) (catch #?(:clj Exception :cljs :default) _ default))))

(defn analyze
  "Port of analyze(b). b = classify(rows). Returns a string-keyed result map."
  [b]
  (let [domains (get b "domains") pdns (get b "pdns") iphist (get b "iphist")
        certs (get b "certs") indicators (get b "indicators") access (get b "access")
        btobs (get b "btobs")

        ;; fast-flux candidates: low TTL + many distinct A/AAAA answers in one observation
        fast-flux0
        (reduce
         (fn [acc p]
           (if (contains? #{":a" ":aaaa"} (get p ":pdns/rrtype"))
             (let [ips (or (get p ":pdns/rrdata") [])
                   ttl (as-int (get p ":pdns/ttl" 999999) 999999)]
               (if (and (<= ttl fast-flux-ttl) (>= (count ips) fast-flux-min-ips))
                 (let [dom (get-in domains [(get p ":pdns/domain") ":domain/fqdn"]
                                   (get p ":pdns/domain"))]
                   (conj acc [dom (count ips) ttl]))
                 acc))
             acc))
         []
         pdns)
        ;; fast_flux.sort(key=lambda r: (r[2], -r[1])) — stable
        fast-flux (vec (sort-by (fn [[_dom nips ttl]] [ttl (- nips)]) fast-flux0))

        ;; hosting concentration + ip moves
        {:keys [prov-load ptype-load ip-moves]}
        (reduce
         (fn [acc h]
           (-> acc
               (update :prov-load omap-inc (get h ":iphist/provider" "?") 1)
               (update :ptype-load omap-inc (get h ":iphist/provider-type" ":unknown") 1)
               (update :ip-moves omap-inc (get h ":iphist/ip" "?") 1)))
         {:prov-load (omap) :ptype-load (omap) :ip-moves (omap)}
         iphist)
        ip-movement (sort-desc-by-val ip-moves)

        ;; IOC load per TLP + category
        {:keys [tlp-load cat-load]}
        (reduce
         (fn [acc i]
           (-> acc
               (update :tlp-load omap-inc (get i ":indicator/tlp" ":unknown") 1)
               (update :cat-load omap-inc (get i ":indicator/category" ":unknown") 1)))
         {:tlp-load (omap) :cat-load (omap)}
         indicators)

        ;; cert-SAN pivots
        cert-pivot0
        (reduce
         (fn [acc c]
           (let [sans (or (get c ":tlscert/san") [])]
             (if (and (sequential? sans) (>= (count sans) 2))
               (conj acc [(get c ":tlscert/subject" (get c ":tlscert/id"))
                          (count sans)
                          (get c ":tlscert/anomaly" ":none")])
               acc)))
         []
         certs)
        ;; cert_pivot.sort(key=lambda r: -r[1]) — stable
        cert-pivot (vec (sort-by (fn [[_subj nsan _anom]] (- nsan)) cert-pivot0))

        ;; G6/G10 encryption self-audit
        access-total (count access)
        access-encrypted (count (filter #(= true (get % ":cti.attr/encrypted")) access))
        plaintext-violations (- access-total access-encrypted)]
    {"fast_flux" fast-flux "prov_load" prov-load "ptype_load" ptype-load
     "ip_movement" ip-movement "tlp_load" tlp-load "cat_load" cat-load
     "cert_pivot" cert-pivot "access_total" access-total
     "access_encrypted" access-encrypted "plaintext_violations" plaintext-violations
     "n_domains" (count domains) "n_pdns" (count pdns) "n_iphist" (count iphist)
     "n_certs" (count certs) "n_ioc" (count indicators) "n_btobs" (count btobs)}))

(defn- lstrip-colon [s] (str/replace (str s) #"^:+" ""))

(defn render-report
  "Port of render_report(b, a) — byte-identical markdown."
  [_b a]
  (let [L (transient [])
        P (fn [s] (conj! L s))]
    (P "# yabai — passive-DNS + CTI threat-intel report")
    (P "")
    (P (str "> ADR-2605301400 §T3 · **kotoba-native** (Datom log; NO RisingWave) · **aggregate-first** · "
            "DEFENSIVE risk context (whose infra, how it moved, which IOCs). yabai SCORES risk; the "
            "Council authorizes enforcement; tadori holds case-anchored evidence. No adherent is "
            "de-anonymised; access-audit PII stays in encrypted envelopes (G6/G10)."))
    (P "")
    (P (str "- domains: **" (get a "n_domains") "**  ·  passive-DNS obs: **" (get a "n_pdns") "**  ·  "
            "IP-history obs: **" (get a "n_iphist") "**  ·  TLS certs: **" (get a "n_certs") "**  ·  IOCs: **" (get a "n_ioc") "**"))
    (P (str "- case-bound BitTorrent observations: **" (get a "n_btobs") "**"))
    (P "")

    (P "## Confidentiality self-audit — G6/G10 (access-audit encryption)")
    (P "")
    (let [status (if (= 0 (get a "plaintext_violations")) "✅ PASS" "❌ FAIL")]
      (P (str "Access-audit records carry accessor identity / IP / device — PII that MUST live in a "
              "`com.etzhayyim.encrypted.*` envelope, never plaintext. **" status "** — "
              (get a "access_encrypted") "/" (get a "access_total") " access records encrypted, "
              "**" (get a "plaintext_violations") "** plaintext-PII violation(s).")))
    (P "")

    (P "## Tor / BitTorrent collection boundary")
    (P "")
    (P (str "Tor exit indicators are public-infrastructure signals. BitTorrent observations are accepted "
            "only when case-bound (`:btobs/case-mandate`) and evidence-backed (`:btobs/evidence-cid`). "
            "They support defensive correlation and preservation, not private-person identification."))
    (P "")

    (P "## Fast-flux candidate domains — low TTL × many A answers")
    (P "")
    (P (str "Domains whose A/AAAA set churns across ≥" fast-flux-min-ips " IPs at TTL ≤" fast-flux-ttl "s "
            "in one observation — a classic resilient-malware / phishing hosting signal. Routed to "
            "takedown / abuse reporting, never to offensive targeting."))
    (P "")
    (P "| domain | distinct IPs | TTL (s) |")
    (P "|---|---:|---:|")
    (doseq [[dom nips ttl] (get a "fast_flux")]
      (P (str "| `" dom "` | " nips " | " ttl " |")))
    (when (empty? (get a "fast_flux"))
      (P "| (none in graph) | | |"))
    (P "")

    (P "## Hosting concentration — observed infra by provider type")
    (P "")
    (P (str "Σ observed IP-history records per hosting provider-type. Surfaces how much observed "
            "infra sits behind cloud/CDN vs bulletproof/residential — a defensive context signal."))
    (P "")
    (P "| provider-type | observations |")
    (P "|---|---:|")
    (doseq [[pt n] (sort-desc-by-val (get a "ptype_load"))]
      (P (str "| `" (lstrip-colon pt) "` | " n " |")))
    (P "")
    (P "| hosting provider | observations |")
    (P "|---|---:|")
    (doseq [[pv n] (take 12 (sort-desc-by-val (get a "prov_load")))]
      (P (str "| " pv " | " n " |")))
    (P "")

    (P "## IOC load — TLP and category distribution")
    (P "")
    (P "| TLP | indicators |  | category | indicators |")
    (P "|---|---:|---|---|---:|")
    (let [tlp (vec (sort-desc-by-val (get a "tlp_load")))
          cat (vec (sort-desc-by-val (get a "cat_load")))]
      (doseq [i (range (max (count tlp) (count cat)))]
        (let [lt (if (< i (count tlp))
                   (str "`" (lstrip-colon (first (nth tlp i))) "` | " (second (nth tlp i)))
                   " | ")
              rc (if (< i (count cat))
                   (str "`" (lstrip-colon (first (nth cat i))) "` | " (second (nth cat i)))
                   " | ")]
          (P (str "| " lt " |  | " rc " |")))))
    (P "")

    (P "## IP-movement churn — most-relocated addresses")
    (P "")
    (P (str "IPs with the most hosting/location-history observations (migration churn = a "
            "re-hosting / evasion signal). Defensive context, never a target-list."))
    (P "")
    (P "| IP | history observations |")
    (P "|---|---:|")
    (doseq [[ip n] (take 12 (get a "ip_movement"))]
      (P (str "| `" (lstrip-colon ip) "` | " n " |")))
    (when (empty? (get a "ip_movement"))
      (P "| (none in graph) | |"))
    (P "")

    (P "## TLS cert-SAN pivots — shared-infrastructure surface")
    (P "")
    (P (str "Certs whose SAN set spans multiple names bridge domains onto shared infra (a CT-log "
            "pivot). `short-lived` / `self-signed` anomalies flagged for review."))
    (P "")
    (P "| cert subject | SAN count | anomaly |")
    (P "|---|---:|---|")
    (doseq [[subj nsan anom] (take 12 (get a "cert_pivot"))]
      (P (str "| `" subj "` | " nsan " | `" (lstrip-colon anom) "` |")))
    (when (empty? (get a "cert_pivot"))
      (P "| (none in graph) | | |"))
    (P "")

    (P "---")
    (P (str "*Generated by `yabai/methods/analyze.py`. HONEST: R0 bounded `:representative` seed; "
            "malicious examples use illustrative example.* names, NOT real-entity attribution; full CTI "
            "ingest (crt.sh CT logs / passive-DNS feeds) is `methods/ingest.py --live` (G7 operator-gated); "
            "vendor feeds are `:feature-flagged-input`, never system-of-record. kotoba Datom log is the "
            "canonical store (ADR-2605262130); the legacy RisingWave CTI graph is retired.*"))
    (str (str/join "\n" (persistent! L)) "\n")))

(defn render-datoms
  "Port of render_datoms(b, a) — byte-identical EDN."
  [_b a]
  (let [L (transient [])
        P (fn [s] (conj! L s))]
    (P ";; yabai — DERIVED CTI signals (ADR-2605301400 §T3). :derived — NOT re-ingested as fact.")
    (P "[")
    (doseq [[dom nips ttl] (get a "fast_flux")]
      (P (str " {:cti/fast-flux-domain " (edn/edn-str dom) " :cti/distinct-ips " nips " :cti/ttl " ttl " :cti/derived true}")))
    (doseq [[pt n] (sort-desc-by-val (get a "ptype_load"))]
      (P (str " {:cti/hosting-concentration " pt " :cti/observations " n " :cti/derived true}")))
    (doseq [[tlp n] (sort-desc-by-val (get a "tlp_load"))]
      (P (str " {:cti/ioc-tlp-load " tlp " :cti/indicators " n " :cti/derived true}")))
    (doseq [[cat n] (sort-desc-by-val (get a "cat_load"))]
      (P (str " {:cti/ioc-category-load " cat " :cti/indicators " n " :cti/derived true}")))
    (doseq [[ip n] (get a "ip_movement")]
      (P (str " {:cti/ip-movement " (edn/edn-str ip) " :cti/history-observations " n " :cti/derived true}")))
    (doseq [[subj nsan anom] (get a "cert_pivot")]
      (P (str " {:cti/cert-pivot " (edn/edn-str subj) " :cti/san-count " nsan " :cti/anomaly " anom " :cti/derived true}")))
    (P (str " {:cti/access-audit-total " (get a "access_total") " :cti/access-encrypted " (get a "access_encrypted") " "
            ":cti/plaintext-violations " (get a "plaintext_violations") " :cti/derived true}"))
    (P (str " {:cti/bittorrent-observations " (get a "n_btobs") " :cti/derived true}"))
    (P "]")
    (str (str/join "\n" (persistent! L)) "\n")))

#?(:clj
   (defn -main
     "CLI entry: analyze a CTI graph EDN → out/intel-report.md + out/cti-signals.kotoba.edn."
     [& argv]
     (let [argv (vec argv)
           here (-> *file* clojure.java.io/file .getParentFile .getParentFile)
           default (let [merged (clojure.java.io/file here "data" "passive-dns.merged.kotoba.edn")]
                     (if (.exists merged)
                       merged
                       (clojure.java.io/file here "data" "seed-passive-dns.kotoba.edn")))
           graph (if (and (seq argv) (not (str/starts-with? (first argv) "--")))
                   (clojure.java.io/file (first argv))
                   default)
           outdir (if (some #{"--out"} argv)
                    (clojure.java.io/file (nth argv (inc (.indexOf argv "--out"))))
                    (clojure.java.io/file here "out"))
           b (edn/classify (edn/load-edn graph))
           a (analyze b)]
       (.mkdirs outdir)
       (spit (clojure.java.io/file outdir "intel-report.md") (render-report b a))
       (spit (clojure.java.io/file outdir "cti-signals.kotoba.edn") (render-datoms b a))
       (println (str "yabai: " (get a "n_domains") " domains · " (get a "n_pdns") " passive-DNS · " (get a "n_certs") " certs · "
                     (get a "n_ioc") " IOCs · " (get a "n_btobs") " BitTorrent obs · fast-flux " (count (get a "fast_flux")) " · "
                     "encryption " (get a "access_encrypted") "/" (get a "access_total") " (viol " (get a "plaintext_violations") ")"))
       (println (str "wrote " (clojure.java.io/file outdir "intel-report.md") " + " (clojure.java.io/file outdir "cti-signals.kotoba.edn")))
       0)))
