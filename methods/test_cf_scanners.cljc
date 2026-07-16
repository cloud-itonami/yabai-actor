#!/usr/bin/env bb
;; yabai — validation of the Cloudflare-zone HTTP-scanner bridge + multi-file graph merge
;; (ADR-2607170800). Run: bb --classpath methods methods/test_cf_scanners.cljc
(ns yabai.methods.test-cf-scanners
  "Pins the probe-path detector, the :scanner IOC bridge (aggregation, confidence tiering,
  deterministic ordering, shared-egress-agnostic pure core) and merge-many (fold many curated
  files into one deduped graph, first-seen wins). These are the durable core the live sweep
  (cf_sweep.cljc) and any offline replay depend on."
  (:require [yabai.methods.ingest :as i]
            [yabai.methods.cf-sweep :as cf]
            [clojure.test :refer [deftest is run-tests]]))

(deftest probe-path-detects-recon-not-legit
  (is (i/probe-path? "/wp-admin/install.php"))
  (is (i/probe-path? "/.env"))
  (is (i/probe-path? "/.git/config"))
  (is (i/probe-path? "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"))
  (is (i/probe-path? "/actuator/env"))
  (is (i/probe-path? "/index.php") "no kotoba zone serves .php → a probe")
  (is (not (i/probe-path? "/")) "the homepage is legit")
  (is (not (i/probe-path? "/chat/aoi-hoshino-neon-tokyo")) "a real app route is legit")
  (is (not (i/probe-path? "/xrpc/ai.gftd.apps.shinshi.listAuthorFeed")) "an xrpc route is legit"))

(deftest scanner-tier-thresholds
  (is (= [900 ":confirmed"] (i/scanner-tier 4 1)))   ;; 4 zones → high
  (is (= [900 ":confirmed"] (i/scanner-tier 1 500))) ;; 500 req → high
  (is (= [820 ":confirmed"] (i/scanner-tier 2 1)))   ;; 2 zones → mid
  (is (= [820 ":confirmed"] (i/scanner-tier 1 50)))  ;; 50 req → mid
  (is (= [700 ":candidate"] (i/scanner-tier 1 3))))  ;; weak → candidate

(def obs
  [{"ip" "1.2.3.4" "cc" "NL" "path" "/.env"      "count" 300 "zone" "gftd.ai"}
   {"ip" "1.2.3.4" "cc" "NL" "path" "/wp-login.php" "count" 300 "zone" "murakumo.cloud"}
   {"ip" "1.2.3.4" "cc" "NL" "path" "/"          "count" 999 "zone" "gftd.ai"}   ;; legit → ignored
   {"ip" "9.9.9.9" "cc" "US" "path" "/.git/config" "count" 4 "zone" "shinshi.club"}])

(deftest bridge-aggregates-and-tiers
  (let [rows (i/bridge-cf-scanners obs "test-src" "authoritative")
        by-ip (into {} (map (juxt #(get % ":indicator/value") identity) rows))
        a (by-ip "1.2.3.4") b (by-ip "9.9.9.9")]
    (is (= 2 (count rows)) "one IOC per source IP")
    (is (= ":scanner" (get a ":indicator/category")))
    (is (= ":ip" (get a ":indicator/type")))
    (is (= "ioc.ip.1-2-3-4" (get a ":indicator/id")) "dotted → dashed ioc.ip id")
    (is (= 900 (get a ":indicator/confidence")) "600 probe-req >= 500 → high tier")
    (is (= ":authoritative" (get a ":indicator/sourcing")))
    (is (= 700 (get b ":indicator/confidence")) "single zone, 4 req → candidate")
    (is (= ":candidate" (get b ":indicator/status")))))

(deftest bridge-legit-only-yields-nothing
  (is (= [] (i/bridge-cf-scanners [{"ip" "5.5.5.5" "path" "/" "count" 10 "zone" "gftd.ai"}] "s" "authoritative"))))

(deftest bridge-deterministic-order
  (let [rows (i/bridge-cf-scanners obs "s" "authoritative")]
    (is (= "1.2.3.4" (get (first rows) ":indicator/value")) "broader/higher-volume IP sorts first")))

(deftest groups->obs-flattens-and-drops-shared-egress
  (let [payload {"data" {"viewer" {"zones"
                 [{"httpRequestsAdaptiveGroups"
                   [{"count" 7 "dimensions" {"clientIP" "8.8.8.8" "clientRequestPath" "/.env" "clientCountryName" "US"}}
                    {"count" 3 "dimensions" {"clientIP" "2a06:98c0:3600::103" "clientRequestPath" "/wp-admin/" "clientCountryName" "US"}}]}]}}}
        out (cf/groups->obs payload "gftd.ai" "2026-07-16")]
    (is (= 1 (count out)) "the Cloudflare shared-egress IP is excluded")
    (is (= "8.8.8.8" (get (first out) "ip")))
    (is (= "gftd.ai" (get (first out) "zone")))))

(deftest merge-many-dedups-first-wins
  (let [seed [{":indicator/id" "x" "src" "seed"}]
        f1   [{":indicator/id" "x" "src" "later"} {":indicator/id" "y"}]
        f2   [{":indicator/id" "z"} "not-a-map" {"no-id" 1}]
        m (i/merge-many [seed f1 f2])]
    (is (= 3 (count m)) "x,y,z once each; junk dropped")
    (is (= "seed" (get (first (filter #(= "x" (get % ":indicator/id")) m)) "src")) "seed wins on dup id")))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'yabai.methods.test-cf-scanners)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
