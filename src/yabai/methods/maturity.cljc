(ns yabai.methods.maturity
  "maturity — the deterministic fitness function the autonomous loop is judged against
  (ADR-0005).

  ADR-0003/0004 gave the watch a judgement and a worldwide supply. Handing that to an
  autonomous agent with the instruction `raise maturity` and no number to raise is how a
  maturity loop becomes theatre: with nothing measurable to move, an agent writes
  documentation and declares progress. This workspace already learned that the expensive way
  — a three-judge LLM panel scored the design system 4.0-5.0/5 while all three missed four
  concrete gaps (tap-target min-height, dvh fallback, one-sided safe-area, theme-color meta),
  and the answer was `90-docs/design-quality/audit.cljc`: a regex-level, LLM-free, browser-free
  fitness function. This is that, for the phishing watch.

  Two layers, and the ORDER between them is the whole design:

    FLOORS   — pass/fail invariants. 36 benign domains must produce no claim; 7 unambiguous
               impersonations must still be caught. A broken floor sets the score to 0 and
               marks the reading `:invalid`.
    GRADIENT — five 0..1 dimensions that a real improvement moves.

  Why floors first: the naive metric (`raise detections`) is optimised fastest by LOOSENING a
  threshold, which is exactly the change that once confirmed `masterclass.com` and `ample.com`
  as phishing. Under this function that move sets the score to ZERO rather than raising it, so
  the cheapest path to a higher number is genuine coverage — more brands, more log shards,
  more corroborated observations. The metric has to be un-gameable before it is motivating.

  No network, no LLM, no clock: the same repo state always yields the same score, so two
  readings are comparable and a loop cannot drift its own baseline."
  (:require [clojure.string :as str]
            [yabai.methods.phish-infra :as phish]
            [yabai.methods.ct-watch :as ct]
            [yabai.methods.yabai-edn :as edn]))

;; ── floors: the calibration sets, shared verbatim with test_phish_infra ──────
(def benign-floor
  "Legitimate or neutral domains. In isolation NONE may produce a phishing claim. Every one
  was confirmed at 900 by some looser variant of the scorer during calibration."
  ["masterclass.com" "mastercard.com" "postmaster.com" "cardmaster.com" "wastewater.com"
   "masterdata.com" "mastermind.io" "whatsnew.com" "whatsapp.com" "whatsup.com"
   "whatsoever.org" "whatsapp.net" "whats.app" "applied.ai" "ample.com" "apples.com"
   "applesauce.com" "pineapple.co.uk" "appleton.us" "apple.com" "linen.example"
   "linear.app" "pipeline.io" "airline.com" "deadline.org" "online.com" "line.me"
   "smbc.co.jp" "smbc-card.com" "google.com" "cloudflare.com" "amazon.co.jp"
   "rakuten.co.jp" "mastercard.us" "watsapp-news.example" "streamline.dev"])

(def impersonation-floor
  "Unambiguous brand impersonations that must be caught with NO infra corroboration."
  ["mastercards.com" "masdercard.com" "mastercand.com" "masteracard.com"
   "whatsaap.com" "whotsapp.com" "whatssapp.com"])

(defn check-floors
  "{:benign-claims [...] :missed-impersonations [...] :ok bool}. Pure."
  []
  (let [claims (->> benign-floor
                    (keep (fn [d]
                            (let [r (first (phish/score-domains [{"domain" d}]))]
                              (when (:status r) [d (:confidence r)]))))
                    vec)
        missed (->> impersonation-floor
                    (remove (fn [d] (:status (first (phish/score-domains [{"domain" d}])))))
                    vec)]
    {:benign-claims claims
     :missed-impersonations missed
     :ok (and (empty? claims) (empty? missed))}))

;; ── gradient dimensions ─────────────────────────────────────────────────────
;; Targets are the point at which a dimension is "mature", NOT a cap on ambition. They are
;; deliberately modest and reachable: a target nobody can move is the same as no metric.
(def targets
  {:brands 25          ; a roster that covers the brands actually impersonated in JP/global phishing
   :logs 6             ; every shard in ct-watch/ct-logs being tailed, not just one
   :observations 2000  ; enough distinct observed domains for co-hosting to have teeth
   :asns 60})          ; infra breadth — one hosting cluster is not a picture of the world

(defn- ratio [n target] (min 1.0 (/ (double (max 0 n)) (double target))))

(defn dimensions
  "Five 0..1 readings from repo state. `graph` is the merged CTI rows, `state` the ct-watch
  cursor map. Pure — callers do the I/O."
  [graph state]
  (let [ind (filter #(and (map? %) (contains? % ":indicator/id")) graph)
        phishing (filter #(= ":phishing" (get % ":indicator/category")) ind)
        iphist (filter #(and (map? %) (contains? % ":iphist/id")) graph)
        asns (->> iphist (keep #(get % ":iphist/asn")) distinct count)
        domains (filter #(and (map? %) (contains? % ":domain/id")) graph)
        ;; a claim resting on BOTH signals is worth more than one resting on a lone typo:
        ;; independence is what keeps the corpus from being one lexical rule's shadow
        corroborated (->> phishing
                          (filter #(#{":bounded-contains" ":contains" ":scrambled" ":cohost-pivot"}
                                    (get % ":indicator/detection")))
                          count)]
    {:brand-coverage (ratio (count phish/default-brands) (:brands targets))
     :log-coverage (ratio (count (keys (:cursors state))) (:logs targets))
     :observation-volume (ratio (count domains) (:observations targets))
     :infra-breadth (ratio asns (:asns targets))
     :signal-independence (if (zero? (count phishing))
                            0.0
                            (double (/ corroborated (count phishing))))}))

(def weights
  "Coverage dominates on purpose: the watch's binding limit is what it can SEE (five
  hand-written brands, one CT shard), not how it decides once it sees something."
  {:brand-coverage 0.30
   :log-coverage 0.25
   :observation-volume 0.20
   :infra-breadth 0.15
   :signal-independence 0.10})

(defn score
  "0..1000, or 0 when a floor is broken. Returns the full reading, not just the number —
  a score with no breakdown cannot be argued with."
  [graph state floors]
  (let [dims (dimensions graph state)
        raw (reduce-kv (fn [acc k w] (+ acc (* w (get dims k 0.0)))) 0.0 weights)]
    {:maturity/score (if (:ok floors) (long (Math/round (* 1000.0 raw))) 0)
     :maturity/valid (:ok floors)
     :maturity/dimensions (into {} (map (fn [[k v]] [k (/ (Math/round (* 1000.0 v)) 1000.0)]) dims))
     :maturity/weights weights
     :maturity/targets targets
     :maturity/floors (select-keys floors [:benign-claims :missed-impersonations :ok])}))

(defn render
  "Human-readable reading. Deliberately states WHY the score is what it is."
  [r]
  (str/join
   "\n"
   (concat
    [(str ";; yabai phishing-watch maturity — GENERATED by src/yabai/methods/maturity.cljc")
     (str ";; DO NOT EDIT BY HAND. Deterministic: no network, no LLM, no clock.")
     (if (:maturity/valid r)
       (str ";; score " (:maturity/score r) "/1000")
       (str ";; score 0/1000 — INVALID: a calibration floor is broken, which is what a"
            "\n;; threshold-loosening 'improvement' looks like from here."))
     ";;"
     ";; Raising this number requires COVERAGE (more brands, more CT shards, more"
     ";; corroborated observations). Loosening a threshold to raise detection counts"
     ";; breaks a floor and drives the score to zero instead."
     ""]
    [(pr-str r) ""])))

;; ── #?(:clj) driver ─────────────────────────────────────────────────────────
#?(:clj (def ^:private repo-root
          (let [d (-> *file* clojure.java.io/file .getParentFile)]
            (.. d getParentFile getParentFile getParentFile))))

#?(:clj
   (defn read-state []
     (let [f (clojure.java.io/file repo-root "data" "ct-watch-state.edn")]
       (if (.exists f)
         (try (clojure.edn/read-string (slurp f)) (catch Exception _ {}))
         {}))))

#?(:clj
   (defn measure!
     "Read repo state, score it, write docs/maturity.edn. The reading is COMMITTED so the
     git history of that one file is the maturity curve — the same growth-log property the
     data plane has."
     []
     (let [graph (edn/load-edn (clojure.java.io/file repo-root "data" "passive-dns.merged.kotoba.edn"))
           r (score graph (read-state) (check-floors))
           out (clojure.java.io/file repo-root "docs" "maturity.edn")]
       (clojure.java.io/make-parents out)
       (spit out (render r))
       r)))

#?(:clj
   (defn -main
     "CLI: print and persist the current maturity reading. Exits non-zero when a floor is
     broken, so a supervisor or CI can treat regression as failure rather than as a low score."
     [& _]
     (let [r (measure!)]
       (println (pr-str (select-keys r [:maturity/score :maturity/valid :maturity/dimensions])))
       (when-not (:maturity/valid r)
         (println "FLOOR BROKEN:" (pr-str (:maturity/floors r)))
         (System/exit 1))
       0)))
