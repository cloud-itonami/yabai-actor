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
            [yabai.methods.maturity :as m]
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
  (is (= [2 1] (mapv :max-edits (take 2 p/default-brands)))
      "the two brands with observed typosquats carry the derived budget")
  (is (every? zero? (map :max-edits (drop 2 p/default-brands)))
      "everything else is gated on evidence, not length — see budget-for"))

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

(deftest shared-infra-ips-neither-give-nor-receive-corroboration
  (let [mk (fn [d asn] {"domain" d "ip" "104.21.1.1" "asn" asn "observed" "2026-07-28"})
        ;; five strong lexical hits, all answering on ONE Cloudflare address
        cdn (p/score-domains (map #(mk % 13335)
                                  ["masdercard.com" "mastercand.com" "masteracard.com"
                                   "mastercards.com" "zxc001.example"]))
        ;; the same five on a VPS ASN, where one address IS one tenant
        vps (p/score-domains (map #(mk % 63949)
                                  ["masdercard.com" "mastercand.com" "masteracard.com"
                                   "mastercards.com" "zxc001.example"]))
        by (fn [rs d] (first (filter #(= d (:domain %)) rs)))]
    (is (every? #(zero? (:cohost-anchors %)) cdn)
        "a CDN address is shared by design — co-location there is not evidence")
    (is (nil? (:status (by cdn "zxc001.example")))
        "so the nameless domain gets no free ride from the CDN cluster")
    (is (= 4 (:cohost-anchors (by vps "zxc001.example")))
        "on dedicated infra the same cluster does corroborate")
    (is (= ":candidate" (:status (by vps "zxc001.example"))))
    (is (= ":confirmed" (:status (by cdn "masdercard.com")))
        "a whole-label typo still stands alone — the CDN rule only removes corroboration"))
  (testing "the list is conservative: an unknown ASN is treated as dedicated"
    (is (not (p/shared-infra? {"asn" 64500})))
    (is (p/shared-infra? {"asn" 13335}))))

(deftest a-sites-own-subdomains-are-not-corroboration
  (testing "one registrant on one host is one observation, however many names it has"
    (let [obs (map (fn [d] {"domain" d "ip" "203.0.113.77" "asn" 64500 "observed" "2026-07-28"})
                   ["applesofttech.com" "www.armo-agro.applesofttech.com"
                    "www.liferehab.applesofttech.com" "www.rspn.applesofttech.com"])
          sc (p/score-domains obs)]
      (is (every? #(zero? (:cohost-anchors %)) sc)
          "found live: these four confirmed each other at 900 before anchors were keyed
           by registrable domain")
      (is (every? #(nil? (:status %)) sc))))
  (testing "registrable-domain collapses subdomains but keeps multi-label suffixes intact"
    (is (= "applesofttech.com" (p/registrable-domain "www.armo-agro.applesofttech.com")))
    (is (= "smbc.co.jp" (p/registrable-domain "login.x.smbc.co.jp")))
    (is (= "a.com" (p/registrable-domain "a.com"))))
  (testing "genuinely distinct registrants on one host still corroborate"
    (let [sc (p/score-domains
              (map (fn [d] {"domain" d "ip" "203.0.113.78" "asn" 64500})
                   ["masdercard.com" "mastercand.com" "masteracard.com" "zxc9.example"]))]
      (is (= 3 (:cohost-anchors (first (filter #(= "zxc9.example" (:domain %)) sc))))))))

(deftest weakest-signals-need-two-neighbours-not-one
  (testing ":contains or :scrambled on a SINGLE anchor peer is not a claim"
    (is (= [0 nil] (p/infra-tier 300 120)))
    (is (= [0 nil] (p/infra-tier 200 120))))
  (testing "two peers is the threshold for the weakest signals"
    (is (= [780 ":candidate"] (p/infra-tier 300 250)))
    (is (= [780 ":candidate"] (p/infra-tier 200 250))))
  (testing "a strong lexical signal still claims on one peer — that is what strength buys"
    (is (= [820 ":candidate"] (p/infra-tier 450 120))))
  (testing "found live: made-LINE-good reached 700 on one peer"
    (is (= ":contains" (:method (p/lexical-hit "test.madelinegood.com"))))))

(deftest live-ct-regression-2026-07-28
  (testing "the first worldwide CT slice this scorer ever saw — 11 lexical candidates,
            of which exactly the two co-hosted whatsapp scam domains earn a claim"
    (let [obs [{"domain" "whatsapp-income-assistance-center.com.ph" "ip" "45.79.222.138" "asn" 63949}
               {"domain" "whatsapp-income-redeeming.com.ph" "ip" "45.79.222.138" "asn" 63949}
               {"domain" "baggybet-online.com" "ip" "172.67.144.143" "asn" 13335}
               {"domain" "www.baggybet-online.com" "ip" "104.21.39.106" "asn" 13335}
               {"domain" "appletonsoap.co.uk" "ip" "23.227.38.65" "asn" 13335}
               {"domain" "ar.royallineb2b.com" "ip" "104.18.40.102" "asn" 13335}
               {"domain" "gst.applefm.com" "ip" "185.53.179.200" "asn" 206834}
               {"domain" "api.moonliner.org" "ip" "208.91.197.27" "asn" 40034}]
          claimed (->> (p/score-domains obs) (filter :status) (mapv :domain))]
      (is (= ["whatsapp-income-assistance-center.com.ph" "whatsapp-income-redeeming.com.ph"]
             claimed))))
  (testing "a two-level public suffix does not swallow the brand"
    (is (= "whatsapp-income-redeeming"
           (p/registrable-label "whatsapp-income-redeeming.com.ph")))))

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
;; The calibration sets live in yabai.methods.maturity — the fitness function IS the floor,
;; and a second copy here would drift the moment the roster grows (ADR-0005 recorded that
;; duplication as debt; this removes it).
(def benign m/benign-floor)
(def impersonations m/impersonation-floor)

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

;; Drawn verbatim from the first six-shard tick (2026-07-29). The point of keeping real
;; names here rather than synthetic ones is that the prefilter's cost is paid in DNS
;; lookups against whatever the world actually issues certificates for, and the world
;; issues a great many certificates for the brands' own regional estates.
(def ^:private brand-owned-infrastructure
  ["s3.cn-north-1.amazonaws.com.cn"
   "accesspoint.vpce-010eefc1e7a3029cf-79tc246b-cn-north-1a.s3.cn-north-1.vpce.amazonaws.com.cn"
   "s3-control.eusc-de-east-1.amazonaws.eu"
   "olmguysms3crpcye5kmx1lvuyrt.memorydb.cn-north-1.amazonaws.com.cn"
   "z30.w.api.fabric.microsoft-int.com"
   "auto-s1216683mi6-pbi-kv-httpszone71.z71.w.api.fabric.microsoft-int.com"
   "zce.userdatafunctions.fabric.microsoft-int.com"])

(deftest brand-estates-are-out-of-scope-at-any-depth
  (testing "a brand's own regional/internal infrastructure never reaches the network stage"
    (let [admitted (filterv #(some? (p/lexical-hit %)) brand-owned-infrastructure)]
      (is (= [] admitted)
          (str "these are the brand's OWN certificates and can never become a claim; "
               "70 of 94 candidates on one 2027 shard were exactly this: "
               (pr-str admitted))))))

(deftest containment-never-spans-a-label-boundary
  (testing "normalization must not invent a brand the registrant never wrote"
    ;; All measured on the 36k-entry tick of 2026-07-29. `sni.cloudflaressl` normalizes to
    ;; `snicloudflaressl`, which contains `icloud` purely because the dot was stripped —
    ;; that admitted every Cloudflare universal-SSL hostname in the slice.
    (is (nil? (p/lexical-hit "031064e8.sni.cloudflaressl.com")))
    (is (nil? (p/lexical-hit "0b2c1daf.prod-eu1.ca.ai.cloud.sap")))
    (is (nil? (p/lexical-hit "x.sni.cloud.example"))))
  (testing "containment WITHIN one label is still a hit"
    ;; The separator-stripping exists for `mast-crade`; removing it entirely would be the
    ;; opposite error, so a hyphen inside a single label must still normalize away.
    (is (some? (p/lexical-hit "supportaccount-signinamazoncom.154-198-163-150.cpanel.site")))
    (is (some? (p/lexical-hit "buscar-appleid-help.info")))))

(deftest subdomain-impersonation-still-caught
  (testing "suffix-matching the home list must not swallow a brand name used as a subdomain"
    ;; Both found live on the same tick that surfaced the noise above. `umadb.ro` and
    ;; `novu.eu` are not brand estates — the brand token sits to the LEFT of a registrable
    ;; domain that belongs to someone else, which is the impersonation, not an exemption.
    (is (some? (p/lexical-hit "microsoft.com.244778543667.umadb.ro")))
    (is (some? (p/lexical-hit "www.microsoft.com.244778543667.umadb.ro")))
    (is (some? (p/lexical-hit "instagram.novu.eu")))))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'yabai.methods.test-phish-infra)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
