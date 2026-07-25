(ns yabai.methods.cf-sweep
  "cf_sweep — yabai LIVE Cloudflare-zone HTTP-scanner collector (ADR-2607170800).

  Sweeps every operator-owned Cloudflare zone via the GraphQL analytics API
  (httpRequestsAdaptiveGroups: clientIP × clientRequestPath × clientCountryName), keeps only
  scanner-probe traffic (ingest/probe-path?), and folds it through the portable
  ingest/bridge-cf-scanners heuristic into :indicator/* :scanner IOCs. The whole kotoba estate
  is run as a HONEYPOT: nothing here serves WordPress/Joomla/PHP/.env/.git, so any request to
  those paths on these zones is unambiguous hostile reconnaissance. yabai only OBSERVES and
  SCORES — it never blocks (the catch-all 200 keeps scanners engaged).

  GATE-G7: a live network pull is operator-gated (`--live` + YABAI_OPERATOR_GATE), matching
  ingest's crt.sh/PDNS discipline. Offline (default) only rebuilds the merged graph from the
  curated on-disk IOC files. Deterministic given fixed --from/--to.

  House style: pure detection lives in ingest (single source of truth); this file is the
  #?(:clj) live+file driver only (bb runtime, dependency-free inline Java for HTTP + Keychain,
  mirroring kotoba.cljc's inline java.security usage). NOT claimed portable."
  (:require [clojure.string :as str]
            [yabai.methods.ingest :as ingest]
            [yabai.methods.yabai-edn :as edn]))

;; operator-owned Cloudflare zones (honeypot estate). id = zoneTag for the GraphQL filter.
(def zones
  [{:id "cf83e7590ebb6ff47a184866e9eddbe6" :name "aozora.app"}
   {:id "fcfa89d40deabcbfae5ab33ae3da70b9" :name "babiniku.net"}
   {:id "54dece4ac787807d4c3410243916a1e6" :name "etzhayyim.com"}
   {:id "63132931facb26812993527da9f85186" :name "gftd.ai"}
   {:id "3bb094bac1fffdb9c61a60093eb267c5" :name "isekai.network"}
   {:id "4ea304cb1d465cb9ba7ea89d8a0d6750" :name "itonami.cloud"}
   {:id "9e5f492f27799f8d32f6d69c08d3ec40" :name "kotoba.digital"}
   {:id "5ad3da692f2367905c257cfcb0c1057c" :name "kotobase.net"}
   {:id "f28dd3b902729a343d2b9d09a2c548e8" :name "manimani.cloud"}
   {:id "9795417e38ef69e173fe37371f937f3e" :name "murakumo.cloud"}
   {:id "1092e6cede04e7c13df4da1794260ef2" :name "nubatama.net"}
   {:id "1527fa6d84bd5c216029c20b4f4810e1" :name "shinshi.club"}
   {:id "0452956d16bf8ea94fadb4d211e16e52" :name "spirit-in-physics.org"}
   {:id "f536ae9c31cbe1083772632718077d34" :name "x402.nexus"}])

;; Cloudflare shared egress (WARP / Workers) — shared infra, not attacker-owned. Never scored
;; (same discipline as ingest's SendGrid/relay exclusion).
(def shared-egress-ips #{"2a06:98c0:3600::103"})

#?(:clj
   (defn- keychain-token
     "CF_API_TOKEN env, else macOS Keychain service `gftd.cf` (read-only, no value logged)."
     []
     (or (System/getenv "CF_API_TOKEN")
         (try
           (let [p (-> (ProcessBuilder. ["security" "find-generic-password" "-s" "gftd.cf" "-w"])
                       (.redirectErrorStream true) .start)
                 out (slurp (.getInputStream p))]
             (.waitFor p)
             (let [t (str/trim out)] (when (seq t) t)))
           (catch Exception _ nil)))))

#?(:clj
   (defn- gql-post
     "POST one GraphQL query to Cloudflare via curl (subprocess, like keychain-token — avoids the
     bb/SCI restriction on HttpURLConnection.getOutputStream). Body is piped over stdin so the
     query's quotes need no shell escaping. Returns the parsed JSON map."
     [token query]
     (let [body (str "{\"query\":" (edn/edn-str query) "}")
           pb (doto (ProcessBuilder.
                     ["curl" "-s" "--max-time" "45" "-X" "POST"
                      "https://api.cloudflare.com/client/v4/graphql"
                      "-H" (str "Authorization: Bearer " token)
                      "-H" "Content-Type: application/json"
                      "--data-binary" "@-"]))
           p (.start pb)]
       (with-open [os (.getOutputStream p)] (.write os (.getBytes body "UTF-8")))
       (let [text (slurp (.getInputStream p))]
         (.waitFor p)
         (ingest/parse-json text)))))

(defn- day-query
  "GraphQL for one zone × one UTC day: request counts by clientIP/path/country."
  [zone-id day]
  (str "{ viewer { zones(filter: {zoneTag: \"" zone-id "\"}) { "
       "httpRequestsAdaptiveGroups(limit: 5000, filter: {date: \"" day "\"}) { "
       "count dimensions { clientIP clientRequestPath clientCountryName } } } } }"))

(defn groups->obs
  "Flatten a Cloudflare httpRequestsAdaptiveGroups payload into normalized obs maps for
  ingest/bridge-cf-scanners. Pure — testable without the network."
  [payload zone-name day]
  (let [zs (get-in payload ["data" "viewer" "zones"])]
    (for [g (get-in (first zs) ["httpRequestsAdaptiveGroups"] [])
          :let [d (get g "dimensions")
                ip (get d "clientIP")]
          :when (and ip (not (shared-egress-ips ip)))]
      {"ip" ip
       "cc" (get d "clientCountryName")
       "path" (get d "clientRequestPath")
       "count" (get g "count")
       "zone" zone-name
       "day" day})))

#?(:clj
   (defn- date-range
     "Inclusive UTC day strings from → to (YYYY-MM-DD)."
     [from to]
     (let [f (java.time.LocalDate/parse from)
           t (java.time.LocalDate/parse to)]
       (loop [d f, acc []]
         (if (.isAfter d t) acc (recur (.plusDays d 1) (conj acc (str d))))))))

;; data/ dir resolved at load time (bb sets *file*). src/yabai/methods/ -> root is 3 levels up.
#?(:clj (def ^:private data-dir
          (let [here (-> *file* clojure.java.io/file .getParentFile)
                repo-root (.. here getParentFile getParentFile getParentFile)]
            (clojure.java.io/file repo-root "data"))))

#?(:clj
   (defn rebuild-merged!
     "Fold the seed + every curated data/*.kotoba.edn IOC/graph file into
     passive-dns.merged.kotoba.edn (the graph analyze/autorun read). seed wins on id; other files
     merge in name order for determinism. This closes the gap where curated IOC files (scanner,
     email-phishing, sms-smishing) were published but never reached the analyzed graph."
     []
     (let [merged-f (clojure.java.io/file data-dir "passive-dns.merged.kotoba.edn")
           seed-f (clojure.java.io/file data-dir "seed-passive-dns.kotoba.edn")
           others (->> (.listFiles data-dir)
                       (filter #(str/ends-with? (.getName %) ".kotoba.edn"))
                       (remove #(#{"passive-dns.merged.kotoba.edn" "seed-passive-dns.kotoba.edn"
                                   "yabai.datoms.kotoba.edn"} (.getName %)))
                       (sort-by #(.getName %)))
           row-seqs (cons (edn/load-edn seed-f) (map edn/load-edn others))
           merged (ingest/merge-many row-seqs)
           header [";; yabai passive-DNS + CTI merged graph — GENERATED by cf_sweep/rebuild-merged!"
                   ";; DO NOT EDIT BY HAND. Fold of seed-passive-dns + all curated data/*.kotoba.edn"
                   (str ";; sources: seed + " (str/join " " (map #(.getName %) others)))]]
       (spit merged-f (edn/to-edn merged header))
       {:rows (count merged)
        :indicators (count (filter #(and (map? %) (contains? % ":indicator/id")) merged))
        :files (inc (count others))})))

#?(:clj
   (defn sweep-live!
     "G7 live pull: sweep all zones over [from..to], write a dated scanner IOC file, and rebuild
     the merged graph. Returns a summary. Requires a CF token."
     [from to & {:keys [source] :or {source "kotoba-cf-zones"}}]
     (let [token (or (keychain-token)
                     (throw (ex-info "no CF_API_TOKEN / Keychain gftd.cf" {})))
           days (date-range from to)
           obs (doall
                (for [z zones, d days
                      o (try (groups->obs (gql-post token (day-query (:id z) d)) (:name z) d)
                             (catch Exception e
                               (binding [*out* *err*] (println "  sweep warn" (:name z) d (.getMessage e))) []))]
                  o))
           iocs (ingest/bridge-cf-scanners obs source "authoritative")
           period (str (str/replace from "-" "") "-" (str/replace to "-" ""))
           fname (str "http-probe-scanners-kotoba-" period ".kotoba.edn")
           header [";; yabai — kotoba EAVT: HTTP vulnerability-scanner source IPs, live Cloudflare sweep"
                   (str ";; Generated by methods/cf_sweep.cljc sweep-live! over " (count zones)
                        " operator-owned zones, window " from " .. " to " (UTC). TLP:CLEAR.")
                   ";; Honeypot posture — observe & score, never block. category :scanner."
                   (str ";; DO NOT EDIT BY HAND — re-run: bb ... cf_sweep.cljc --live --from " from " --to " to)]
           out-file (clojure.java.io/file data-dir fname)]
       (spit out-file (edn/to-edn iocs header))
       (let [merged (rebuild-merged!)]
         {:zones (count zones) :days (count days) :observations (count obs)
          :scanner-iocs (count iocs) :file (.getName out-file)
          :merged-rows (:rows merged) :merged-indicators (:indicators merged)}))))

#?(:clj
   (defn -main
     "CLI: [--live --from YYYY-MM-DD --to YYYY-MM-DD] | (default) offline rebuild-merged!."
     [& args]
     (let [argv (vec args)
           opt (fn [f] (let [i (.indexOf argv f)] (when (>= i 0) (get argv (inc i)))))
           live? (some #{"--live"} argv)]
       (if live?
         (let [from (or (opt "--from") (throw (ex-info "--live needs --from/--to" {})))
               to (or (opt "--to") from)]
           (println "G7 live CF sweep" from ".." to)
           (prn (sweep-live! from to)))
         (do (println "offline rebuild-merged! (pass --live --from --to for a live pull)")
             (prn (rebuild-merged!)))))))
