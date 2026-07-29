#!/usr/bin/env bb
;; yabai — validation of the maturity fitness function (ADR-0005).
;; Run: bb --classpath src:test test/yabai/methods/test_maturity.cljc
(ns yabai.methods.test-maturity
  "The point of this file is the anti-gaming test.

  A fitness function handed to an autonomous agent is only as good as its cheapest exploit.
  For a detector the cheapest exploit is loosening a threshold: detections go up, the number
  looks better, the detector is worse. So the load-bearing assertion here is not `the score
  is computed correctly` — it is `the exploit makes the score go DOWN, to zero`."
  (:require [yabai.methods.maturity :as m]
            [yabai.methods.phish-infra :as phish]
            [clojure.test :refer [deftest is testing run-tests]]))

(def graph
  [{":domain/id" "domain.a"} {":domain/id" "domain.b"}
   {":iphist/id" "h1" ":iphist/asn" "asn.1"} {":iphist/id" "h2" ":iphist/asn" "asn.2"}
   {":indicator/id" "i1" ":indicator/category" ":phishing" ":indicator/detection" ":whole-label-typo"}
   {":indicator/id" "i2" ":indicator/category" ":phishing" ":indicator/detection" ":cohost-pivot"}
   {":indicator/id" "i3" ":indicator/category" ":scanner"}])

(def state {:cursors {"argon2026h2" 1 "nimbus2026" 2}})

(deftest dimensions-read-repo-state-not-opinion
  (let [d (m/dimensions graph state)]
    (is (= (/ (double (count phish/default-brands)) (double (:brands m/targets)))
           (:brand-coverage d)))
    (is (= (/ 2.0 (double (:logs m/targets))) (:log-coverage d))
        "two cursors, measured against the target rather than a hardcoded shard count")
    (is (= (/ 2.0 2000.0) (:observation-volume d)))
    (is (= (/ 2.0 60.0) (:infra-breadth d)) "distinct :iphist/asn, not row count")
    (is (= 0.5 (:signal-independence d))
        "one of the two phishing claims rests on a corroborating signal"))
  (testing "no phishing indicators means no independence to report, not a divide by zero"
    (is (= 0.0 (:signal-independence (m/dimensions [] {}))))))

(deftest dimensions-are-capped-so-one-axis-cannot-carry-the-score
  (let [huge (into graph (map (fn [i] {":domain/id" (str "d" i)}) (range 5000)))]
    (is (= 1.0 (:observation-volume (m/dimensions huge state))))
    (is (<= (:maturity/score (m/score huge state {:ok true})) 1000))))

(deftest score-is-zero-when-a-floor-is-broken
  (let [broken {:ok false :benign-claims [["ample.com" 900]] :missed-impersonations []}]
    (is (= 0 (:maturity/score (m/score graph state broken))))
    (is (false? (:maturity/valid (m/score graph state broken))))
    (is (pos? (:maturity/score (m/score graph state {:ok true}))))))

(deftest edit-budget-is-gated-on-evidence-not-length
  (testing "only brands actually seen impersonated in this repo's corpora carry a budget"
    (is (= [["mastercard" 2] ["whatsapp" 1]]
           (vec (keep #(when (pos? (:max-edits %)) [(:brand %) (:max-edits %)])
                      phish/default-brands)))))
  (testing "a :target brand is a hypothesis and gets none, whatever its length"
    (is (zero? (phish/budget-for {:brand "softbank" :seen :target})))
    (is (= 1 (phish/budget-for {:brand "softbank" :seen :corpus})))
    (is (pos? (phish/default-max-edits "softbank"))
        "length alone would have granted one — evidence is what withholds it"))
  (testing "why: whatsapp and softbank are both 8 letters, but softback is a real word"
    (let [loose (mapv #(assoc % :max-edits (phish/default-max-edits (:brand %)))
                      phish/default-brands)]
      (is (:status (first (phish/score-domains [{"domain" "softback.example"}] loose)))
          "with a length-derived budget the ordinary word is confirmed as phishing")
      (is (nil? (:status (first (phish/score-domains [{"domain" "softback.example"}]))))
          "with the evidence gate it is not")))
  (testing "every roster brand clears the minimum token length"
    (is (every? #(>= (count (:brand %)) phish/min-brand-token) phish/default-brands))))

(deftest roster-growth-must-carry-its-own-benign-probes
  (testing "each brand with a budget has a near-miss in the floor set"
    (doseq [b (filter #(pos? (:max-edits %)) phish/default-brands)]
      (is (some #(and (not= % (:brand b))
                      (<= (phish/osa-distance (phish/normalize-label
                                               (phish/registrable-label %))
                                              (:brand b))
                          (+ 2 (:max-edits b))))
                m/benign-floor)
          (str "no benign near-miss probes " (:brand b) " — the floor would pass vacuously"))))
  (testing "each brand's own domains are in the floor, so the victim is never reported"
    (is (every? (fn [b] (some (set m/benign-floor) (:home b)))
                phish/default-brands))))

;; ── the assertion this whole namespace exists for ───────────────────────────
(deftest loosening-a-threshold-lowers-the-score-instead-of-raising-it
  (testing "the real floors hold on the shipped calibration"
    (let [f (m/check-floors)]
      (is (:ok f) (str "shipped scorer broke its own floor: " (pr-str f)))
      (is (= [] (:benign-claims f)))
      (is (= [] (:missed-impersonations f)))))
  (testing "the cheapest way to raise detection counts breaks a floor"
    ;; This is the exact edit that once shipped: a flat 3-edit budget on every brand.
    ;; It DOES raise detections — and it confirms masterclass.com / whatsnew.com / ample.com.
    (let [loose (mapv #(assoc % :max-edits 3) phish/default-brands)
          claimed (->> m/benign-floor
                       (keep (fn [d]
                               (let [r (first (phish/score-domains [{"domain" d}] loose))]
                                 (when (:status r) d))))
                       vec)]
      (is (seq claimed)
          "if a loosened budget stopped producing false positives this test is meaningless")
      (is (some #{"masterclass.com"} claimed))
      (is (some #{"ample.com"} claimed))
      ;; …and under this fitness function that shows up as ZERO, not as progress.
      (let [floors {:ok false :benign-claims (mapv (fn [d] [d 900]) claimed)
                    :missed-impersonations []}]
        (is (= 0 (:maturity/score (m/score graph state floors)))
            "loosening must be scored strictly worse than doing nothing")))))

(deftest coverage-is-the-cheap-honest-way-up
  (testing "adding a brand raises the score without touching any threshold"
    (let [narrow (with-redefs [phish/default-brands (vec (take 5 phish/default-brands))]
                   (m/score graph state {:ok true}))
          base (m/score graph state {:ok true})]
      (is (> (:maturity/score base) (:maturity/score narrow))
          "the 25-brand roster scores above the original five")
      (is (< (:brand-coverage (m/dimensions graph state)) 1.0)
          "and the target still has headroom — a dimension pinned at 1.0 has stopped measuring")))
  (testing "tailing another CT shard does too"
    (is (> (:maturity/score (m/score graph (assoc-in state [:cursors "xenon2026h2"] 3) {:ok true}))
           (:maturity/score (m/score graph state {:ok true}))))))

(deftest reading-explains-itself
  (let [r (m/score graph state {:ok true})
        txt (m/render r)]
    (is (contains? r :maturity/dimensions) "a bare number cannot be argued with")
    (is (contains? r :maturity/targets))
    (is (re-find #"DO NOT EDIT BY HAND" txt))
    (is (re-find #"COVERAGE" txt) "the file states how to raise it honestly")))

;; ── issuance coverage ───────────────────────────────────────────────────────
;; Numbers below are the real 2026-07-29 measurement: heads advancing ~2.3M/hour against
;; a 333/hour consumption, which is the condition every other dimension read as progress.
(defn- hist [& samples] {:history {"argon2026h2" (vec samples)}})

(deftest issuance-coverage-measures-the-race-not-the-pile
  (testing "consumption over issuance, not observations accumulated"
    (is (= 0.5 (m/issuance-coverage (hist {:t 0 :head 1000 :cursor 0}
                                          {:t 3600000 :head 2000 :cursor 500})))))
  (testing "keeping up reads 1.0, and overshoot cannot exceed it"
    (is (= 1.0 (m/issuance-coverage (hist {:t 0 :head 1000 :cursor 0}
                                          {:t 3600000 :head 2000 :cursor 5000})))))
  (testing "the real reading is a rounding error away from zero, and must say so"
    (let [c (m/issuance-coverage (hist {:t 0 :head 2213173502 :cursor 2204353586}
                                       {:t 3600000 :head 2215486171 :cursor 2204356918}))]
      (is (< c 0.01) (str "measured " c " — a watch this far behind must not read as mature")))))

(deftest unmeasurable-coverage-is-nil-never-a-number
  (testing "a single sample cannot yield a rate"
    (is (nil? (m/issuance-coverage (hist {:t 0 :head 1000 :cursor 0}))))
    (is (nil? (m/issuance-coverage {}))))
  (testing "a quiet upstream is not achieved coverage"
    ;; If the head stops moving, consumed/issued would divide by zero — and any fallback
    ;; that returns 1.0 would let a dead log list look like a solved problem.
    (is (nil? (m/issuance-coverage (hist {:t 0 :head 1000 :cursor 0}
                                         {:t 3600000 :head 1000 :cursor 0}))))))

(deftest unmeasured-dimensions-are-dropped-and-declared
  (let [floors {:ok true :benign-claims [] :missed-impersonations []}
        r (m/score [] {:cursors {"argon2026h2" 1}} floors)]
    (testing "nil dimension is neither scored as 0 nor as 1"
      (is (not (contains? (:maturity/dimensions r) :issuance-coverage)))
      (is (= [:issuance-coverage] (:maturity/incomplete r)))
      (is (< (:maturity/scored-out-of r) 1.0)
          "the caller must be able to see the score is out of partial weight"))
    (testing "renormalization, so a missing dimension does not silently deflate the score"
      ;; log-coverage 1/12 is the only non-zero measured dimension here; the score must be
      ;; that reading against the weight that actually applied, not against 1.0.
      (is (pos? (:maturity/score r))))))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'yabai.methods.test-maturity)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
