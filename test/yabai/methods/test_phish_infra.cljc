#!/usr/bin/env bb
;; yabai — validation of the brand-impersonation / phishing-infrastructure scorer (ADR-0003).
;; Run: bb --classpath src:test test/yabai/methods/test_phish_infra.cljc
(ns yabai.methods.test-phish-infra
  "Pins the two scoring signals and — more importantly — the CALIBRATION between them.

  The legacy tool this replaces stamped every collected row `confidence >= 0.95`. The whole
  point of the port is that a claim now has to be earned, so the tests that matter most are
  the two adversarial sets at the bottom: 36 legitimate domains that must produce NO claim in
  isolation, and 7 unambiguous impersonations that must still be caught. Loosening any
  threshold (edit budget, boundary rule, anchor threshold, tier table) fails those first."
  (:require [yabai.methods.phish-infra :as p]
            [clojure.test :refer [deftest is testing run-tests]]))

;; ── lexical primitives ──────────────────────────────────────────────────────
(deftest registrable-label-strips-public-suffix
  (is (= "bq-line" (p/registrable-label "bq-line.me")))
  (is (= "mastercard" (p/registrable-label "MasterCard.com")) "case-folded")
  (is (= "smbc" (p/registrable-label "smbc.co.jp")) "multi-label suffix")
  (is (= "login.smbc.example" (p/registrable-label "login.smbc.example.co.jp")))
  (is (= "qaz11" (p/registrable-label "qaz11.help"))))

(deftest osa-counts-transposition-as-one-edit
  (is (= 1 (p/osa-distance "mastercard" "mastercrad")) "adjacent swap = 1, not 2")
  (is (= 0 (p/osa-distance "apple" "apple")))
  (is (= 5 (p/osa-distance "apple" "")))
  (is (= 1 (p/osa-distance "mastercard" "masdercard"))))

(deftest max-edits-scales-down-with-brand-length
  (is (= 2 (p/default-max-edits "mastercard")))
  (is (= 1 (p/default-max-edits "whatsapp")))
  (is (= 0 (p/default-max-edits "apple")) "a 5-letter token gets no edit budget")
  (is (= 0 (p/default-max-edits "line")))
  (is (= [2 1 0 0 0] (mapv :max-edits p/default-brands)) "roster uses the derived rule"))

(deftest containment-boundary-is-asymmetric
  (testing "leading position or a separator/digit before the token = bounded"
    (is (= ":bounded-contains" (:method (p/lexical-hit "applestorls.com"))))
    (is (= ":bounded-contains" (:method (p/lexical-hit "smbcservice.com"))))
    (is (= ":bounded-contains" (:method (p/lexical-hit "bq-line.me"))))
    (is (= ":bounded-contains" (:method (p/lexical-hit "account-whatsapp.com")))))
  (testing "a merely TRAILING match is not bounded — English words end in brand-like suffixes"
    (is (= ":contains" (:method (p/lexical-hit "pipeline.io"))))
    (is (= ":contains" (:method (p/lexical-hit "airline.com"))))
    (is (= ":contains" (:method (p/lexical-hit "deadline.org"))))))

(deftest home-domains-are-never-scored
  (is (nil? (p/lexical-hit "apple.com")))
  (is (nil? (p/lexical-hit "mastercard.com")))
  (is (nil? (p/lexical-hit "line.me")))
  (is (nil? (p/lexical-hit "smbc-card.com"))
      "a home domain is exempt from EVERY brand, not just its own (it scrambles near mastercard)")
  (is (nil? (p/lexical-hit "mastercard.co.jp"))
      "an exact brand label is out of scope on any TLD — that is a different detector"))

;; ── tier table: the two hard rules ──────────────────────────────────────────
(deftest lone-weak-lexical-makes-no-claim
  (is (= [0 nil] (p/infra-tier 450 0)) ":bounded-contains alone → no phishing claim")
  (is (= [0 nil] (p/infra-tier 300 0)) ":contains alone → no claim")
  (is (= [0 nil] (p/infra-tier 200 0)) ":scrambled alone → no claim")
  (is (= [900 ":confirmed"] (p/infra-tier 600 0))
      "only a whole-label typo stands on its own"))

(deftest cohosting-alone-never-confirms
  (is (= [700 ":candidate"] (p/infra-tier 0 400)))
  (is (= [600 ":candidate"] (p/infra-tier 0 250)))
  (is (= [0 nil] (p/infra-tier 0 120)) "a single anchor peer is not enough")
  (is (= [900 ":confirmed"] (p/infra-tier 450 250)) "weak lexical + corroboration = confirmed")
  (is (= [950 ":confirmed"] (p/infra-tier 600 250)) "both signals = top confidence"))

;; ── co-hosting corroboration ────────────────────────────────────────────────
(def cohost-obs
  ;; 5 whole-label typos + 1 random name on one IP; 1 lone typo and 1 lone random elsewhere
  (concat
   (map (fn [d] {"domain" d "ip" "203.0.113.10" "asn" 64500 "asn_org" "TEST" "asn_country" "ZZ"
                 "observed" "2026-04-19"})
        ["masdercard.com" "mastercand.com" "masteracard.com" "mastercards.com" "mastercrad.com"
         "zxc001.example"])
   [{"domain" "maslercard.com" "ip" "203.0.113.20" "observed" "2026-04-19"}
    {"domain" "qaz11.example" "ip" "203.0.113.30" "observed" "2026-04-19"}]))

(deftest cohosting-lifts-a-nameless-domain-but-not-an-isolated-one
  (let [by-dom (into {} (map (juxt :domain identity) (p/score-domains cohost-obs)))]
    (is (= [":candidate" 700] ((juxt :status :confidence) (by-dom "zxc001.example")))
        "5 anchors on the same IP lift it to candidate — but co-hosting alone never confirms")
    (is (nil? (:lexical (by-dom "zxc001.example"))) "the lift is infra-only, no brand claimed")
    (is (nil? (:status (by-dom "qaz11.example")))
        "same shape of name, alone on its IP → no claim")
    (is (= 5 (:cohost-anchors (by-dom "zxc001.example"))))
    (is (= 4 (:cohost-anchors (by-dom "masdercard.com")))
        "a domain is never its own corroboration")))

(deftest weak-lexical-hits-are-not-anchors
  (let [obs (concat
             (map (fn [d] {"domain" d "ip" "203.0.113.40" "observed" "2026-04-19"})
                  ;; all :scrambled (200) — below anchor-threshold
                  ["mastcrada.com" "mastcrade.com" "mastcrads.com" "mastcaort.com" "mastecaort.com"])
             [{"domain" "random55.example" "ip" "203.0.113.40" "observed" "2026-04-19"}])
        by-dom (into {} (map (juxt :domain identity) (p/score-domains obs)))]
    (is (zero? (:cohost-anchors (by-dom "random55.example")))
        "a cluster of weak hits cannot bootstrap-confirm itself")
    (is (nil? (:status (by-dom "random55.example"))))))

;; ── EAVT bridge ─────────────────────────────────────────────────────────────
(deftest bridge-emits-domain-pdns-iphist-and-only-earned-indicators
  (let [scored (p/score-domains cohost-obs)
        rows (p/bridge-phish-infra scored "test-src" "authoritative")
        of (fn [k] (filter #(contains? % k) rows))
        ind (into {} (map (juxt #(get % ":indicator/value") identity) (of ":indicator/id")))]
    (is (= 8 (count (of ":domain/id"))) "every observation is a :domain/* fact")
    (is (= 8 (count (of ":pdns/id"))) "each resolving domain gets one A record")
    (is (= 3 (count (of ":iphist/id"))) "one :iphist/* row per distinct IP, deduped")
    (is (= 7 (count (of ":indicator/id")))
        "qaz11.example earned no claim, so it has no :indicator/* row")
    (is (nil? (ind "qaz11.example")))
    (let [a (ind "masdercard.com")]
      (is (= ":domain" (get a ":indicator/type")))
      (is (= ":phishing" (get a ":indicator/category")))
      (is (= "ioc.dom.masdercard-com" (get a ":indicator/id")))
      (is (= "mastercard" (get a ":indicator/brand-target")))
      (is (= ":whole-label-typo" (get a ":indicator/detection")))
      (is (= 950 (get a ":indicator/confidence")) "typo + corroboration"))
    (is (= ":cohost-pivot" (get (ind "zxc001.example") ":indicator/detection"))
        "an infra-only claim names no brand")
    (is (nil? (get (ind "zxc001.example") ":indicator/brand-target"))))
  (testing "deterministic"
    (is (= (p/bridge-phish-infra (p/score-domains cohost-obs))
           (p/bridge-phish-infra (p/score-domains (reverse cohost-obs))))
        "input order does not change the output graph")))

(deftest deferring-to-a-curated-file-keeps-the-facts-and-drops-only-the-claim
  (let [scored (p/score-domains cohost-obs)
        rows (p/bridge-phish-infra scored "test-src" "authoritative"
                                   #{"ioc.dom.masdercard-com"})
        of (fn [k] (filter #(contains? % k) rows))]
    (is (= 6 (count (of ":indicator/id")))
        "the deferred domain contributes no duplicate :indicator/* claim")
    (is (empty? (filter #(= "masdercard.com" (get % ":indicator/value")) (of ":indicator/id"))))
    (is (some #(= "domain.masdercard-com" (get % ":domain/id")) (of ":domain/id"))
        "but its :domain/* fact stays")
    (is (some #(= "pdns.masdercard-com.a" (get % ":pdns/id")) (of ":pdns/id"))
        "and so does the resolving-IP observation — that is what this corpus adds")))

;; ── abuse drafts (never sent) ───────────────────────────────────────────────
(deftest drafts-cover-confirmed-only-and-report-what-they-skip
  (let [scored (p/score-domains
                (map (fn [d] {"domain" d "ip" "203.0.113.10" "asn" 135377
                              "asn_org" "UCLOUD-HK-AS-AP, HK" "asn_country" "HK"
                              ;; masdercard is CONFIRMED but its registrar has no published
                              ;; abuse contact — it must surface in :skipped, not vanish
                              "registrar" (if (= d "masdercard.com") "Nowhere Registrar LLC" "Dynadot Inc")
                              "observed" "2026-04-19"})
                     ["masdercard.com" "mastercand.com" "masteracard.com" "mastercards.com"
                      "mastercrad.com" "zxc001.example"]))
        {:keys [drafts skipped]} (p/abuse-drafts scored)
        by-cluster (into {} (map (juxt :cluster identity) drafts))]
    (is (= 2 (count drafts)) "one ASN cluster + one registrar cluster with a known contact")
    (is (= "abuse@ucloud.cn" (:to (by-cluster [":asn" 135377]))))
    (is (= "abuse@dynadot.com" (:to (by-cluster [":registrar" "Dynadot Inc"]))))
    (is (= 1 (count skipped)) "the registrar with no published abuse contact is reported")
    (is (= ":no-abuse-contact" (:reason (first skipped))))
    (is (re-find #"masdercard\.com" (:body (by-cluster [":asn" 135377]))))
    (is (not (re-find #"qaz11" (:body (by-cluster [":asn" 135377]))))))
  (testing "rendering takes the date as an argument — no clock read, so drafts are reproducible"
    (let [eml (p/draft->eml {:to "a@b" :subject "s" :body "b"} "2026-04-19")]
      (is (re-find #"(?m)^Date: 2026-04-19" eml))
      (is (re-find #"(?m)^From: abuse-liaison@etzhayyim\.com" eml)))))

;; ── CALIBRATION REGRESSION — the tests that guard the claim itself ──────────
(def benign
  "Legitimate or neutral domains. In isolation (no co-hosting corroboration) NONE of these
  may produce a phishing claim. Every one of them was confirmed at 900 by some looser
  variant of this scorer during calibration."
  ["masterclass.com" "mastercard.com" "postmaster.com" "cardmaster.com" "wastewater.com"
   "masterdata.com" "mastermind.io" "whatsnew.com" "whatsapp.com" "whatsup.com"
   "whatsoever.org" "whatsapp.net" "whats.app" "applied.ai" "ample.com" "apples.com"
   "applesauce.com" "pineapple.co.uk" "appleton.us" "apple.com" "linen.example"
   "linear.app" "pipeline.io" "airline.com" "deadline.org" "online.com" "line.me"
   "smbc.co.jp" "smbc-card.com" "google.com" "cloudflare.com" "amazon.co.jp"
   "rakuten.co.jp" "mastercard.us" "watsapp-news.example" "streamline.dev"])

(def impersonations
  "Unambiguous brand impersonations that must be caught with NO infra corroboration."
  ["mastercards.com" "masdercard.com" "mastercand.com" "masteracard.com"
   "whatsaap.com" "whotsapp.com" "whatssapp.com"])

(deftest no-claim-on-isolated-benign-domains
  (let [claimed (->> benign
                     (map (fn [d] (first (p/score-domains [{"domain" d}]))))
                     (filter :status)
                     (mapv (juxt :domain :confidence)))]
    (is (= [] claimed) (str "false positives: " (pr-str claimed)))))

(deftest impersonations-caught-without-corroboration
  (let [missed (->> impersonations
                    (remove (fn [d] (:status (first (p/score-domains [{"domain" d}])))))
                    vec)]
    (is (= [] missed) (str "missed: " (pr-str missed)))))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'yabai.methods.test-phish-infra)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
