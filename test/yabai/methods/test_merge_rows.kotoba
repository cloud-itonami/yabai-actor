#!/usr/bin/env bb
;; yabai — validation of the seed+bridged threat-intel dedup-merge.
;; Run:  bb --classpath 20-actors 20-actors/yabai/methods/test_merge_rows.cljc
(ns yabai.methods.test-merge-rows
  "Validation of merge-rows — yabai's seed+bridged dedup-merge for the threat-intel graph. It
  concatenates seed rows then bridged rows and keeps the FIRST seen of each id (so a curated seed
  row wins over a bridged duplicate), identifying a row by the first present of several id-key
  shapes (\":domain/id\", \":pdns/id\", \":tlscert/id\", …). It was ISOLATED. Pins seed-wins
  precedence, the multi-shape id detection, and the skipping of non-maps / id-less rows — a
  regression there would either drop real intel or let a bridged row clobber a curated seed row.

  (The id keys are string-typed in the Datom layer — \":domain/id\", not the keyword :domain/id —
  same convention as kamado #2163; tests build records with the string keys accordingly.)"
  (:require [yabai.methods.ingest :as i]
            [clojure.test :refer [deftest is run-tests]]))

(deftest seed-wins-over-a-bridged-duplicate-and-new-ids-are-added
  (let [merged (i/merge-rows [{":domain/id" "a" "src" "seed"}]
                             [{":domain/id" "a" "src" "bridge"} {":domain/id" "b" "src" "bridge"}])]
    (is (= 2 (count merged)) "one duplicate dropped, one new added")
    (is (= "seed" (get (first merged) "src")) "the seed row wins the id collision (first seen)")
    (is (= "b" (get (second merged) ":domain/id")) "the genuinely-new bridged id is appended")))

(deftest a-row-is-identified-by-the-first-present-id-key-shape
  ;; any of the id-key shapes makes a row identifiable; two rows sharing a ":pdns/id" dedup, while a
  ;; ":tlscert/id" row is a distinct entity
  (let [merged (i/merge-rows [{":pdns/id" "p1"}] [{":pdns/id" "p1"} {":tlscert/id" "t1"}])]
    (is (= 2 (count merged)) "\":pdns/id\" p1 dedups; the \":tlscert/id\" row is distinct")))

(deftest non-maps-and-id-less-rows-are-skipped
  (let [merged (i/merge-rows [{":domain/id" "a"}] ["not-a-map" 42 {} {"no-id-key" 1}])]
    (is (= 1 (count merged)) "only the one identifiable seed row survives")
    (is (= "a" (get (first merged) ":domain/id")))))

(deftest empty-and-single-inputs
  (is (= [] (i/merge-rows [] [])) "empty inputs → empty merge")
  (is (= 1 (count (i/merge-rows [{":domain/id" "a"}] []))) "a lone seed row passes through"))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'yabai.methods.test-merge-rows)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
