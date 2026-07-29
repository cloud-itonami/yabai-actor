#!/usr/bin/env bb
;; yabai — validation of the CT-log supply collector (ADR-0004).
;; Run: bb --classpath src:test test/yabai/methods/test_ct_watch.cljc
(ns yabai.methods.test-ct-watch
  "Pins the offline-testable half of the CT watch: MerkleTreeLeaf field arithmetic, name
  normalization, the pure prefilter that keeps the firehose off the network, and the slice
  planner that murakumo fans out. The live half (get-sth / get-entries / DNS / Cymru) is
  G7-gated and verified by running a tick, not here."
  (:require [yabai.methods.ct-watch :as w]
            [yabai.methods.phish-infra :as phish]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing run-tests]]))

(deftest u24-is-big-endian-and-unsigned
  (is (= 0 (w/u24 [0 0 0] 0)))
  (is (= 1 (w/u24 [0 0 1] 0)))
  (is (= 0x10000 (w/u24 [1 0 0] 0)))
  (is (= 0xffffff (w/u24 [-1 -1 -1] 0))
      "JVM bytes are signed; 0xff must not read back as -1")
  (is (= 258 (w/u24 [9 9 0 1 2] 2)) "reads at the offset, not the head"))

(deftest entry-type-and-cert-span
  (let [x509 (into (vec (repeat 10 0)) [0 0 0 0 4])          ; entry_type 0, len 4
        precert (into (vec (repeat 10 0)) [0 1])]            ; entry_type 1
    (is (= 0 (w/entry-type x509)))
    (is (= 1 (w/entry-type precert)))
    (is (= [:leaf 15 4] (w/cert-span x509 nil))
        "x509_entry: the cert follows the uint24 length at offset 12")
    (is (= [:extra 3 7] (w/cert-span precert [0 0 7]))
        "precert: the SAN-bearing cert is in extra_data, not the leaf")
    (is (nil? (w/cert-span precert nil))
        "a precert with no extra_data is skipped, not guessed at")
    (is (nil? (w/cert-span (into (vec (repeat 10 0)) [9 9]) nil))
        "unknown entry types are skipped")))

(deftest normalize-fqdn-rejects-what-is-not-a-domain
  (is (= "foo.example.com" (w/normalize-fqdn "*.Foo.EXAMPLE.com ")) "wildcard + case + space")
  (is (= "a.b.co.jp" (w/normalize-fqdn "a.b.co.jp")))
  (is (nil? (w/normalize-fqdn "1.2.3.4")) "SANs carry IPs too")
  (is (nil? (w/normalize-fqdn "localhost")) "no dot")
  (is (nil? (w/normalize-fqdn "")) )
  (is (nil? (w/normalize-fqdn "hello world.com")) "junk names are dropped"))

(deftest prefilter-keeps-the-firehose-off-the-network
  (testing "only names with a lexical signal are worth a DNS lookup"
    (is (= ["bq-line.me" "masdercard.com" "whatsapp-income-redeeming.com.ph"]
           (w/interesting-names
            ["www.appliancesolutionsusa.com" "masdercard.com" "*.bq-line.me"
             "whatsapp-income-redeeming.com.ph" "tanstia.teamproit.com"]))))
  (testing "`sni.cloudflaressl.com` is NOT a candidate — this was a bug, not a price.

            This block previously asserted the opposite and called it a MEASURED COST of
            the wider roster: `sn-icloud-flaressl` contains `icloud`, so one of the most
            common names in CT was admitted on every tick, and I pinned that here as a
            visible price worth paying. It was not a price. `icloud` only appears there
            because normalize-label strips the dot between `sni` and `cloudflaressl`, so
            the hit was against a string no registrant ever wrote. Documenting a defect
            carefully is not the same as noticing it; the pin made the cost visible and
            simultaneously made it look intended, which is why it survived until a 36k-entry
            tick made the volume impossible to ignore.

            :contains now requires the brand to survive inside a single dot-label."
    (is (= [] (w/interesting-names ["db2c8a47.sni.cloudflaressl.com"])))
    (is (nil? (phish/lexical-hit "db2c8a47.sni.cloudflaressl.com")))
    (is (nil? (:status (first (phish/score-domains
                               [{"domain" "db2c8a47.sni.cloudflaressl.com"}]))))))
  (testing "a brand's own domain is never a candidate — it is the victim"
    (is (= [] (w/interesting-names ["apple.com" "line.me" "mastercard.com"]))))
  (testing "deduped, wildcard-folded and sorted, so a tick is reproducible"
    (is (= ["bq-line.me"] (w/interesting-names ["*.bq-line.me" "bq-line.me" "BQ-LINE.ME"])))))

(deftest plan-slices-covers-the-range-exactly
  (let [s (w/plan-slices 100 210 4)]
    (is (= 4 (count s)))
    (is (= 100 (:start (first s))))
    (is (= 210 (:end (last s))))
    (is (= 110 (reduce + (map #(- (:end %) (:start %)) s))) "no gaps, no overlap")
    (is (apply <= (mapcat (juxt :start :end) s)) "contiguous and ordered"))
  (testing "a remainder is spread over the leading slices, never dropped"
    (is (= 10 (reduce + (map #(- (:end %) (:start %)) (w/plan-slices 0 10 3))))))
  (testing "degenerate inputs do not produce work"
    (is (nil? (w/plan-slices 5 5 4)))
    (is (nil? (w/plan-slices 10 5 4)))))

(deftest fanout-batch-runs-somewhere-that-exists
  (let [state {:cursors {"argon2026h2" 1000 "nimbus2026" 5000}}
        b (w/fanout-batch state ["argon2026h2" "nimbus2026"] 2 500)
        cmds (map :cmd (:tasks b))]
    (is (= 4 (count (:tasks b))) "slices-per-log x logs")
    (is (= ["ct-argon2026h2-0" "ct-argon2026h2-1" "ct-nimbus2026-0" "ct-nimbus2026-1"]
           (mapv :id (:tasks b))))
    (testing "the command targets the staged directory, not the operator's checkout.
              The previous --plan emitted `cd <local repo-root> && bb -cp src`, which is
              why it had never once been executed: no fleet node has that path."
      (is (every? #(str/includes? % w/remote-src-dir) cmds))
      (is (not-any? #(str/includes? % "/Users/") cmds)))
    (testing "slices sit AHEAD of the cursor, so the fleet widens coverage rather than
              re-reading the band the resident tick is already consuming"
      (let [starts (map #(Long/parseLong (second (re-find #":start (\d+)" %))) cmds)]
        (is (every? #(> % 1000) (take 2 starts)))
        (is (apply < (take 2 starts)) "slices are disjoint and ordered")))))

(deftest known-logs-are-shaped-like-ct-endpoints
  (is (contains? w/ct-logs w/default-log))
  (is (every? #(re-matches #"https://.+/" %) (vals w/ct-logs))
      "get-sth / get-entries are appended directly, so each base must end in /"))

#?(:clj
   (deftest sh*-surfaces-stderr-and-the-exit-code
     (testing "a failing subprocess must be distinguishable from a succeeding one"
       (let [ok (#'w/sh* ["git" "--version"])
             bad (#'w/sh* ["git" "--no-such-flag-exists"])]
         (is (zero? (:exit ok)))
         (is (re-find #"git version" (:out ok)))
         (is (pos? (:exit bad))
             "the exit code is the only reliable success signal")
         (is (seq (:err bad))
             "git reports failure on stderr; a collector that reads only stdout sees nothing")
         (is (empty? (:out bad))
             "this is precisely why grepping stdout for /error|rejected|fatal/ reported a
              non-fast-forward push as {:pushed true} on 2026-07-28 — stdout was empty")))))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'yabai.methods.test-ct-watch)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
