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

    FLOORS   — pass/fail invariants. Every benign domain must produce no claim; every
               unambiguous impersonation must still be caught. A broken floor sets the score
               to 0 and marks the reading `:invalid`. The benign set GROWS WITH THE ROSTER —
               see benign-floor for why a fixed set passes vacuously.
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
  "Legitimate or neutral domains. In isolation NONE may produce a phishing claim.

  This set must GROW WITH THE ROSTER. A floor that only probes the brands it was written
  for passes vacuously the moment new brands are added — the check would keep reporting
  `ok` while the new tokens quietly manufacture false positives. Every brand carrying an
  edit budget needs at least one near-miss here, and every brand's own domains belong in
  the list too (the scorer must never report the victim)."
  [;; original five — each was confirmed at 900 by some looser variant during calibration
   "masterclass.com" "mastercard.com" "postmaster.com" "cardmaster.com" "wastewater.com"
   "masterdata.com" "mastermind.io" "whatsnew.com" "whatsapp.com" "whatsup.com"
   "whatsoever.org" "whatsapp.net" "whats.app" "applied.ai" "ample.com" "apples.com"
   "applesauce.com" "pineapple.co.uk" "appleton.us" "apple.com" "linen.example"
   "linear.app" "pipeline.io" "airline.com" "deadline.org" "online.com" "line.me"
   "smbc.co.jp" "smbc-card.com" "google.com" "cloudflare.com" "amazon.co.jp"
   "rakuten.co.jp" "mastercard.us" "watsapp-news.example" "streamline.dev"
   ;; THE probe that locks the length rule: `finance` is one edit from `binance`. It stays
   ;; unclaimed only because a 7-letter token gets a zero edit budget. Raise binance's
   ;; budget to 1 and finance.com becomes phishing.
   "finance.com" "finances.example" "refinance.example"
   ;; near-misses for the brands that DO carry a budget (mastercard 2, whatsapp/microsoft/
   ;; instagram/facebook/telegram/coinbase/softbank 1)
   "telegraph.co.uk" "faceboard.example" "combase.example" "softbase.example"
   "microsoftware.example" "instagraph.example" "coinbased.example" "softback.example"
   ;; containment collisions — these must stay unclaimed WITHOUT infra corroboration
   "amazonas.com" "amazonia.org" "googolplex.example" "googlemaps-guide.example"
   "mizuhomachi.example" "sagawa-ryokan.example" "saisonnier.example" "lineup.example"
   "paypaltips.example" "netflixed.example" "mercatinos.example"
   ;; every roster brand's own domains — never report the victim
   "icloud.com" "google.co.jp" "amazon.com" "microsoft.com" "outlook.com" "paypal.com"
   "netflix.com" "instagram.com" "facebook.com" "fb.com" "telegram.org" "t.me"
   "coinbase.com" "binance.com" "mizuhobank.co.jp" "mufg.jp" "docomo.ne.jp"
   "softbank.jp" "paypay.ne.jp" "mercari.com" "saisoncard.co.jp" "sagawa-exp.co.jp"
   ;; A brand's own INFRASTRUCTURE, on subdomains. Measured 2026-07-28: one 300-entry slice
   ;; of a 2027 CT shard produced 447 candidates, 409 of them `*.amazonaws.com` VPC
   ;; endpoints and MSK brokers, because `amazonaws` starts with `amazon` and home matching
   ;; compared exact FQDNs. These probe that home now resolves on the registrable domain.
   "bucket.vpce-0f92515731b3b8c6f-z8xiemy0.s3.ap-northeast-1.vpce.amazonaws.com"
   "tls.canary82eb823279d0.c9zy2z.c3.kafka.af-south-1.amazonaws.com"
   "s3-accesspoint.dualstack.us-gov-east-1.amazonaws.com"
   "login.microsoftonline.com" "x.blob.core.windows.net" "fonts.gstatic.com"
   "scontent.fbcdn.net" "www.paypalobjects.com" "occ-0-1.nflxvideo.net"])

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
  ;; Raised from 25 to 50 on 2026-07-28: the roster reached 25 and the dimension pinned at
  ;; 1.0, which is the metric saying the target stopped being informative. A target nobody
  ;; can move is the same as no metric — and so is one already met.
  {:brands 50          ; a roster that covers the brands actually impersonated in JP/global phishing
   ;; Raised 6 -> 12 on 2026-07-28 for the same reason as :brands — all six configured
   ;; shards are now tailed and the dimension pinned at 1.0. The public log list carries
   ;; more operators (DigiCert Wyvern/Sphinx, Sectigo, Let's Encrypt Oak, TrustAsia); the
   ;; headroom is what makes adding them worth an agent's time.
   :logs 12            ; shards actually tailed, across operators — not just Google+Cloudflare
   :observations 2000  ; enough distinct observed domains for co-hosting to have teeth
   :asns 60})          ; infra breadth — one hosting cluster is not a picture of the world

(defn- ratio [n target] (min 1.0 (/ (double (max 0 n)) (double target))))

(defn issuance-coverage
  "What fraction of the world's certificate issuance this watch actually consumes.

  Every other dimension here measures OUR PILE — how many brands we listed, how many
  domains we accumulated. None of them can see the watch losing a race. Measured
  2026-07-29: the six cursors sat 29,206,861 entries behind their heads while the tick
  consumed 1,998 entries/hour, and argon2026h2's head alone advanced ~2.3M entries in the
  time we took 333 from it. Every pile-counting dimension read that as progress, because
  the pile was in fact growing. A score that cannot see a three-order-of-magnitude deficit
  is not measuring maturity, and an agent optimizing it would never be pushed to close one.

  So: consumption rate / issuance rate, summed across shards, from the `:history` samples
  ct-watch appends each tick. No clock is read here — the timestamps are data.

  Returns nil when fewer than two samples exist for every shard. nil is not zero: `score`
  drops the dimension and says so, because inventing a number for something never measured
  is the failure this whole dimension exists to catch."
  [state]
  (let [spans (for [[_log h] (:history state)
                    :let [h (vec h)]
                    :when (>= (count h) 2)
                    :let [a (first h) b (peek h)
                          dt (- (:t b) (:t a))]
                    :when (pos? dt)]
                {:issued (max 0 (- (:head b) (:head a)))
                 :consumed (max 0 (- (:cursor b) (:cursor a)))})
        issued (reduce + 0 (map :issued spans))
        consumed (reduce + 0 (map :consumed spans))]
    (cond
      (empty? spans) nil
      ;; A head that never moved means the logs went quiet, not that we achieved coverage.
      ;; Claiming 1.0 here would let a dead upstream look like a solved problem.
      (zero? issued) nil
      :else (min 1.0 (/ (double consumed) (double issued))))))

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
     :issuance-coverage (issuance-coverage state)
     :observation-volume (ratio (count domains) (:observations targets))
     :infra-breadth (ratio asns (:asns targets))
     :signal-independence (if (zero? (count phishing))
                            0.0
                            (double (/ corroborated (count phishing))))}))

(def weights
  "Coverage dominates on purpose: the watch's binding limit is what it can SEE, not how it
  decides once it sees something.

  Rebalanced 2026-07-29 to seat `:issuance-coverage` as the joint-heaviest term and to cut
  `:observation-volume` in half. Volume was the most flattering dimension and the least
  informative: it rises whenever the tick runs at all, so it read a watch falling three
  orders of magnitude behind the firehose as steady progress. Counting what we hold is
  worth something; it is not worth as much as whether we are keeping up."
  {:brand-coverage 0.25
   :log-coverage 0.20
   :issuance-coverage 0.25
   :observation-volume 0.10
   :infra-breadth 0.12
   :signal-independence 0.08})

(defn score
  "0..1000, or 0 when a floor is broken. Returns the full reading, not just the number —
  a score with no breakdown cannot be argued with."
  [graph state floors]
  (let [dims (dimensions graph state)
        ;; A dimension that could not be measured is dropped and its weight renormalized
        ;; away, NOT scored as zero and NOT scored as one. Zero would punish a fresh clone
        ;; for having no history yet; one would let "never measured" masquerade as
        ;; "perfect". Either way the caller is owed the list, so `:incomplete` names every
        ;; dropped dimension and the score is explicitly out of the weight that remained.
        measured (into {} (remove (fn [[_ v]] (nil? v)) dims))
        incomplete (vec (sort (remove (set (keys measured)) (keys dims))))
        live-weight (reduce + 0.0 (map weights (keys measured)))
        raw (if (pos? live-weight)
              (/ (reduce-kv (fn [acc k w] (+ acc (* w (get measured k 0.0)))) 0.0
                            (select-keys weights (keys measured)))
                 live-weight)
              0.0)
        r3 (fn [v] (/ (Math/round (* 1000.0 (double v))) 1000.0))]
    (cond-> {:maturity/score (if (:ok floors) (long (Math/round (* 1000.0 raw))) 0)
             :maturity/valid (:ok floors)
             :maturity/dimensions (into {} (map (fn [[k v]] [k (r3 v)]) measured))
             :maturity/weights weights
             :maturity/targets targets
             :maturity/floors (select-keys floors [:benign-claims :missed-impersonations :ok])}
      (seq incomplete)
      (assoc :maturity/incomplete incomplete
             :maturity/scored-out-of (r3 live-weight)))))

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
       (when-let [inc* (seq (:maturity/incomplete r))]
         (println (str "NOT MEASURED: " (str/join ", " (map name inc*))
                       " — score is out of " (:maturity/scored-out-of r)
                       " of the weight, not 1.0. Treat it as provisional.")))
       (when-not (:maturity/valid r)
         (println "FLOOR BROKEN:" (pr-str (:maturity/floors r)))
         (System/exit 1))
       0)))
