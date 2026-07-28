#!/usr/bin/env bb
;; yabai — validation of the telephony institution-impersonation scorer (line_infra).
;; Run: bb --classpath src:test test/yabai/methods/test_line_infra.cljc
(ns yabai.methods.test-line-infra
  "Pins the two scoring signals and the CALIBRATION between them, the same way
  test_phish_infra does for domains.

  The tests that matter most are the two adversarial sets at the bottom: 24 ordinary numbers
  that must produce NO claim in isolation, and 6 unambiguous impersonation shapes that must
  still be caught. Loosening any threshold (edit budget, prefix minimum, anchor threshold,
  tier table) fails those first.

  And one property that is not a calibration question at all but a safety one: there is no
  input to this namespace that produces a genuineness verdict. `no-genuineness-verdict-ever`
  enforces that absence."
  (:require [yabai.methods.line-infra :as l]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing run-tests]]))

;; ── primitives ──────────────────────────────────────────────────────────────

(deftest digits-strips-formatting
  (is (= "9110" (l/digits "#9110")))
  (is (= "0570016811" (l/digits "0570-016811")))
  (is (= "81352516811" (l/digits "+81-3-5251-6811")))
  (is (= "188" (l/digits "188")))
  (is (= "" (l/digits "unknown"))))

(deftest osa-counts-transposition-as-one-edit
  (is (= 1 (l/osa-distance "0570016811" "0570016181")) "adjacent swap = 1, not 2")
  (is (= 0 (l/osa-distance "9110" "9110")))
  (is (= 1 (l/osa-distance "0570016811" "0570016812"))))

(deftest max-edits-scales-down-with-number-length
  (is (= 2 (l/default-max-edits "0570-016811")) "10 digits")
  (is (= 2 (l/default-max-edits "03-5251-6811")) "also 10 digits once formatting is stripped")
  (is (= 1 (l/default-max-edits "0120-9248")) "8 digits")
  (is (= 0 (l/default-max-edits "#9110")) "a 4-digit shortcode gets no edit budget")
  (is (= 0 (l/default-max-edits "188"))))

;; ── presentation signal ─────────────────────────────────────────────────────

(deftest inbound-only-shortcode-presented-as-origin-is-a-spoof-by-construction
  (testing "a consultation shortcode cannot be the ORIGIN of a call, so presenting one needs no corroboration -- the telephony analogue of phish_infra's whole-label typo"
    (doseq [n ["#9110" "9110" "188" "0120-924-839"]]
      (let [h (l/presentation-hit n)]
        (is (= ":inbound-only-spoof" (:method h)) (str n))
        (is (= 600 (:score h)) (str n))))))

(deftest exact-match-on-a-published-non-shortcode-number-makes-no-claim
  (testing "presenting 金融庁's real published number is exactly what a genuine call from it looks like; this scorer cannot tell them apart and must not pretend to"
    (is (nil? (l/presentation-hit "0570-016811")))
    (is (nil? (l/presentation-hit "0570016811")))
    (is (nil? (l/presentation-hit "03-5251-6811")))))

(deftest whole-number-typo-is-caught-within-the-scaled-budget
  (let [h (l/presentation-hit "0570-016812")]
    (is (= ":whole-number-typo" (:method h)))
    (is (= 1 (:distance h))))
  (let [h (l/presentation-hit "0570-016181")]
    (is (= ":whole-number-typo" (:method h)) "transposition inside the budget")))

(deftest prefix-borrow-needs-six-shared-digits-not-an-area-code
  (testing "reproducing the institution's exchange as well as its area code"
    (is (= ":prefix-borrow" (:method (l/presentation-hit "0570-016000")))))
  (testing "a merely shared area code is not evidence -- 03 covers all of Tokyo"
    (is (nil? (l/presentation-hit "03-1234-5678")))
    (is (nil? (l/presentation-hit "03-9999-0000")))))

(deftest outbound-able-numbers-are-never-scored
  (testing "an institution that may legitimately call out must never be reported as impersonating itself -- never report the victim"
    (let [insts (mapv #(assoc % :kind :outbound-able) l/institutions)]
      (doseq [i l/institutions]
        (is (nil? (l/presentation-hit (:number i) insts)) (str (:number i)))))))

(deftest empty-or-withheld-presentation-scores-nothing
  (is (nil? (l/presentation-hit "")))
  (is (nil? (l/presentation-hit "unknown")))
  (is (nil? (l/presentation-hit "非通知"))))

;; ── tier table: the two hard rules, inherited from phish_infra ──────────────

(deftest lone-weak-presentation-makes-no-claim
  (is (= [0 nil] (l/infra-tier 450 0)) ":whole-number-typo alone -> no claim")
  (is (= [0 nil] (l/infra-tier 300 0)) ":prefix-borrow alone -> no claim")
  (is (= [0 nil] (l/infra-tier 200 0)) ":scrambled alone -> no claim"))

(deftest route-concentration-alone-never-confirms
  (doseq [r [120 250 400 999]]
    (is (not= ":confirmed" (second (l/infra-tier 0 r)))
        (str "route " r " with no presentation signal must not confirm"))))

(deftest inbound-only-spoof-confirms-alone
  (is (= ":confirmed" (second (l/infra-tier 600 0))))
  (is (= [950 ":confirmed"] (l/infra-tier 600 250))))

(deftest weak-signal-plus-route-corroboration-can-confirm
  (is (= [900 ":confirmed"] (l/infra-tier 450 250)))
  (is (= [820 ":candidate"] (l/infra-tier 450 120))))

;; ── the safety property ─────────────────────────────────────────────────────

(deftest no-genuineness-verdict-ever
  (testing "nil status means NO CLAIM, never 'this call is safe'. No input to the tier table produces anything resembling a legitimacy assertion."
    (let [statuses (for [p [0 200 300 450 600 9999] r [0 120 250 400 9999]]
                     (second (l/infra-tier p r)))]
      (is (every? #(contains? #{nil ":candidate" ":confirmed"} %) statuses))
      (is (not-any? #(and % (re-find #"genuine|legitimate|safe|clean|verified" %)) statuses))))
  (testing "and an unscored observation is bridged as a fact with NO indicator attached"
    (let [scored (l/score-lines [{"presented" "03-1234-5678" "route" "trunk-x"}])
          {lines ":line" inds ":indicator"} (l/bridge-line-infra scored)]
      (is (= 1 (count lines)))
      (is (= 0 (count inds)) "no claim must mean no indicator row, not a negative indicator")
      (is (not-any? #(str/includes? (str %) "genuine") lines)))))

;; ── route concentration ─────────────────────────────────────────────────────

(def spoof-cluster
  "Six numbers on one procurement route, four of them presenting inbound-only shortcodes."
  [{"presented" "#9110" "route" "sip-trunk-A" "carrier" "carrier-1" "origin_cc" "??"}
   {"presented" "188" "route" "sip-trunk-A" "carrier" "carrier-1" "origin_cc" "??"}
   {"presented" "0120-924-839" "route" "sip-trunk-A" "carrier" "carrier-1" "origin_cc" "??"}
   {"presented" "0120-344-999" "route" "sip-trunk-A" "carrier" "carrier-1" "origin_cc" "??"}
   ;; no presentation signal at all -- earns everything it gets from the route
   {"presented" "050-0000-1111" "route" "sip-trunk-A" "carrier" "carrier-1" "origin_cc" "??"}
   ;; a weak signal that the route corroborates into a confirmation
   {"presented" "0570-016812" "route" "sip-trunk-A" "carrier" "carrier-1" "origin_cc" "??"}])

(deftest route-corroboration-lifts-a-weak-signal-but-not-a-blank-one
  (let [scored (l/score-lines spoof-cluster)
        by-num (into {} (map (juxt :presented identity)) scored)]
    (testing "the blank number reaches :candidate on route evidence alone, never :confirmed"
      (let [blank (by-num "050-0000-1111")]
        (is (zero? (:presentation-score blank)))
        (is (pos? (:route-score blank)))
        (is (= ":candidate" (:status blank)))))
    (testing "the weak typo IS confirmed once the route corroborates it"
      (let [typo (by-num "0570-016812")]
        (is (= 450 (:presentation-score typo)))
        (is (= ":confirmed" (:status typo)))))
    (testing "and the shortcode spoofs are confirmed on their own signal"
      (is (= ":confirmed" (:status (by-num "#9110")))))))

(deftest unknown-numbers-cannot-bootstrap-confirm-themselves
  (testing "a cluster with NO strong presentation hit produces no anchors, so route score is 0 for every member -- the same property that stops phish_infra's co-hosting from self-confirming"
    (let [obs (mapv (fn [i] {"presented" (str "050-0000-" (format "%04d" i)) "route" "sip-trunk-B"})
                    (range 1 21))
          scored (l/score-lines obs)]
      (is (every? #(zero? (:route-score %)) scored))
      (is (every? #(nil? (:status %)) scored)))))

(deftest route-rollup-counts-without-asserting-complicity
  (let [rollup (l/route-concentration (l/score-lines spoof-cluster))
        a (first (filter #(= "sip-trunk-A" (:route %)) rollup))]
    (is (= 6 (:observations a)))
    (is (= 5 (:anchors a)) "4 shortcode spoofs + the typo, once the route confirms it")
    (is (pos? (:confirmed a)))
    (is (not-any? #(str/includes? (str %) "bulletproof") rollup)
        "counts only -- operator complicity is an attribution claim these observations do not support")))

;; ── adversarial set 1: ordinary numbers must produce NO claim in isolation ──

(def benign
  "24 ordinary Japanese numbers. In isolation (no route corroboration) every one of these
  must produce no claim at all. Same role as test_phish_infra's 36-domain benign set."
  ["03-1234-5678" "03-5251-0000" "03-0000-6811" "06-6543-2100" "052-111-2222"
   "011-222-3333" "092-333-4444" "045-555-6666" "075-777-8888" "078-999-0000"
   "090-1234-5678" "080-8765-4321" "070-1111-2222" "050-3333-4444" "0120-000-111"
   "0120-111-222" "0120-999-888" "0570-000-000" "0570-100-100" "0800-123-4567"
   "0180-993-388" "0985-11-2233" "0287-44-5566" "0138-77-8899"])

(deftest no-claim-on-isolated-ordinary-numbers
  (let [claimed (->> benign
                     (map (fn [n] {"presented" n "route" (str "solo-" n)}))
                     l/score-lines
                     (filter :status)
                     (map :presented))]
    (is (empty? claimed)
        (str "these must produce no claim in isolation: " (pr-str claimed)))))

;; ── adversarial set 2: unambiguous impersonations must still be caught ──────

(def impersonations
  "6 shapes that must be caught. Four are inbound-only shortcode spoofs (confirmed alone);
  two are near-misses that must at least be caught once a route corroborates them."
  [{"presented" "#9110" "route" "solo-1" :expect ":confirmed"}
   {"presented" "188" "route" "solo-2" :expect ":confirmed"}
   {"presented" "0120-924-839" "route" "solo-3" :expect ":confirmed"}
   {"presented" "0120-344-999" "route" "solo-4" :expect ":confirmed"}
   {"presented" "0570-016812" "route" "sip-trunk-A" :expect ":confirmed"}
   {"presented" "0570-016000" "route" "sip-trunk-A" :expect ":candidate"}])

(deftest impersonation-set-is-fully-caught
  (let [obs (concat (mapv #(dissoc % :expect) impersonations)
                    ;; two anchors so the route can corroborate the weak ones
                    [{"presented" "#9110" "route" "sip-trunk-A"}
                     {"presented" "188" "route" "sip-trunk-A"}])
        scored (l/score-lines obs)
        by-num (into {} (map (juxt :presented identity)) scored)]
    (doseq [{:strs [presented] :keys [expect]} impersonations]
      (is (= expect (:status (by-num presented)))
          (str presented " expected " expect
               " got " (:status (by-num presented)))))))

(deftest bridge-emits-indicators-only-for-tiered-numbers
  (let [scored (l/score-lines spoof-cluster)
        {lines ":line" inds ":indicator"} (l/bridge-line-infra scored)]
    (is (= (count spoof-cluster) (count lines)) "every observation stays a :line/* fact")
    (is (= (count (filter :status scored)) (count inds)))
    (doseq [i inds]
      (is (some #{(get i ":indicator/kind")}
                [":institution-impersonation-line" ":line-route-concentration"]))
      (is (some #{(get i ":indicator/status")} [":confirmed" ":candidate"])))
    (testing "a route-only candidate names NO institution -- we did not observe which one was impersonated, and guessing would be the fabrication this scorer exists to remove"
      (let [route-only (first (filter #(= ":line-route-concentration" (get % ":indicator/kind")) inds))]
        (is (some? route-only))
        (is (nil? (get route-only ":indicator/institution")))
        (is (nil? (get route-only ":indicator/method")))
        (is (= ":candidate" (get route-only ":indicator/status"))
            "route evidence alone can never reach :confirmed")))
    (testing "and a presentation hit DOES name the institution"
      (let [named (first (filter #(= ":institution-impersonation-line" (get % ":indicator/kind")) inds))]
        (is (some? (get named ":indicator/institution")))
        (is (some? (get named ":indicator/method")))))))

(deftest scoring-is-deterministic
  (is (= (l/score-lines spoof-cluster) (l/score-lines spoof-cluster)))
  (is (= (l/score-lines (reverse spoof-cluster)) (l/score-lines spoof-cluster))
      "input order must not change the result -- rows are sorted by presented number"))

#?(:clj (when (= *file* (System/getProperty "babashka.file")) (run-tests)))
