(ns yabai.methods.line-infra
  "line_infra — yabai institution-impersonation scorer for TELEPHONY, the sibling of
  phish_infra (ADR-0003) on the other side of the same attack.

  phish_infra answers \"does this DOMAIN impersonate a brand, and does its hosting
  corroborate that?\". This answers the same question for the channel that actually carries
  the 2026 corporate fraud wave: 警察庁's own 2025 figures put ニセ警察詐欺 at 11,014
  recognized cases / ¥100.5B, with the initial contact being a PHONE CALL in 99.0% of them.

  Two INDEPENDENT, deterministic signals, the same shape and the same hard rules:

    1. PRESENTATION — does the presented calling number impersonate an institution's
       published number? (inbound-only-shortcode spoof / whole-number OSA typo /
       boundary-anchored prefix borrow / scrambled near-miss)
    2. ROUTE-CONCENTRATION — does this number share a carrier route with other numbers that
       already have a STRONG presentation hit? A number with no presentation signal at all
       earns nothing on its own, but sitting on the same route as a cluster of confirmed
       police-shortcode spoofs is itself the observation.

  Only strong presentation hits are ANCHORS, so a cluster of unknown numbers can never
  bootstrap-confirm itself. An institution's own outbound-capable numbers are never scored —
  never report the victim.

  ── Why enumeration alone cannot work (the reason this is a ROUTE scorer) ──
  警察庁 recorded 86,180 international numbers used in these crimes in 11 months of 2025 =
  ~258/day. A blocklist refreshed weekly therefore carries a standing backlog of ~1,806
  live-but-unlisted numbers at all times. Scoring individual numbers can never close that
  gap; scoring the ROUTE they are procured through can, which is exactly the co-hosting
  insight phish_infra already encodes for IPs.

  ── HARD RULES (inherited verbatim from phish_infra, ADR-0003) ──
    · Route concentration ALONE never reaches `:confirmed`.
    · A LONE weak presentation signal emits NO `:indicator/*` at all — the observation stays
      a `:line/*` fact with no claim attached.
    · An institution's own outbound-capable number is out of scope entirely.

  ── ONE ADDITIONAL HARD RULE, specific to telephony ──
    · **No genuineness verdict, ever.** `nil` status means \"no claim\", NOT \"this call is
      safe\". Caller-id is trivially spoofable, so a scorer that could return \"legitimate\"
      would launder a spoofed number into an attestation. There is no code path here that
      produces one, and `test_line_infra` enforces the absence. This is the same property
      cloud-itonami/meibo states as its G11 no-inbound-attestation gate; the two are designed
      to be used together — yabai scores infrastructure, meibo hands back the published
      window to call instead.

  CONSTITUTIONAL framing (unchanged): yabai SCORES, the Council authorizes enforcement,
  tadori holds case evidence. Nothing here has transport and nothing here sends anything.

  STATUS: offline-default, like every other yabai method. There is no live telephony feed —
  the calibration corpus below is the artifact, built from numbers the institutions
  themselves publish (verified live 2026-07-28) plus labelled adversary shapes. Wiring a real
  carrier/CDR feed is a separate, operator-gated wave and is NOT implied by this namespace.

  House style: ':…' keyword strings stay strings; every scoring fn is pure and portable."
  (:require [clojure.string :as str]))

;; ── institution roster ──────────────────────────────────────────────────────

(defn digits
  "Keep only digits. `#9110` → `9110`, `0570-016811` → `0570016811`,
  `+81-3-5251-6811` → `81352516811`. Formatting is not signal."
  [s]
  (str/replace (str s) #"[^0-9]" ""))

(defn default-max-edits
  "Whole-number OSA budget for a published number, scaled by length: `(len - 6) / 2`,
  floored at 0 — the identical rule phish_infra uses for brand tokens, and for the identical
  reason: the budget has to shrink faster than the token grows, because a whole-number
  near-miss is the one weak-form signal strong enough to anchor.

  → a 10-digit number (0570016811) gets 2 · an 8-digit gets 1 · a 4-digit shortcode gets 0.

  Short numbers are not thereby unprotected: `#9110` and `188` are `:inbound-only`, and any
  call PRESENTING an inbound-only number is a spoof by construction (see
  `presentation-hit`), which is a stronger signal than any typo budget."
  [number]
  (max 0 (quot (- (count (digits number)) 6) 2)))

(def default-institutions
  "Numbers the institutions themselves publish. Every entry was verified live on the
  institution's own page 2026-07-28 — the same provenance discipline
  cloud-itonami/meibo's `data/verification-window.edn` holds, and these are the same
  numbers, deliberately kept in sync by hand rather than by a code dependency (yabai and
  meibo are independent actors and must stay independently deployable).

  :inbound-only  — a consultation shortcode/hotline that cannot legitimately appear as the
                   ORIGIN of a call. Presenting one is a spoof by construction.
  :outbound-able — a number the institution may legitimately call out from. NEVER scored:
                   reporting it would be reporting the victim.
  :published     — published contact number, neither asserted inbound-only nor known to
                   place outbound calls. Eligible for typo/prefix signals only."
  [{:institution "警察庁 警察相談専用電話" :number "#9110" :kind :inbound-only
    :source "https://www.npa.go.jp/goiken_index.html"}
   {:institution "消費者ホットライン" :number "188" :kind :inbound-only
    :source "https://www.kokusen.go.jp/map/"}
   {:institution "警察庁 匿名通報ダイヤル" :number "0120-924-839" :kind :inbound-only
    :source "https://www.npa.go.jp/bureau/safetylife/sos47/"}
   {:institution "警察庁 未公開株通報専用窓口" :number "0120-344-999" :kind :inbound-only
    :source "https://www.npa.go.jp/bureau/safetylife/sos47/"}
   {:institution "金融庁 金融サービス利用者相談室" :number "0570-016811" :kind :published
    :source "https://www.fsa.go.jp/receipt/soudansitu/index.html"}
   {:institution "金融庁 金融サービス利用者相談室 (IP電話)" :number "03-5251-6811" :kind :published
    :source "https://www.fsa.go.jp/receipt/soudansitu/index.html"}])

(defn- with-budget [inst]
  (assoc inst :max-edits (or (:max-edits inst) (default-max-edits (:number inst)))))

(def institutions (mapv with-budget default-institutions))

;; ── OSA (Damerau-Levenshtein with adjacent transposition) ───────────────────
;; Transposition matters for digits even more than for letters: `0570016811` →
;; `0570016181` is one swap, which plain Levenshtein charges 2 for.

(defn osa-distance
  "Optimal string alignment distance between a and b. Pure; O(mn) time, O(n) space.
  Same implementation as phish_infra's — deliberately duplicated rather than shared, because
  yabai's methods are each independently portable (see phish_infra's own house-style note)."
  [a b]
  (let [a (vec a) b (vec b) m (count a) n (count b)]
    (cond
      (zero? m) n
      (zero? n) m
      :else
      (loop [i 1, prev2 nil, prev (vec (range (inc n)))]
        (if (> i m)
          (peek prev)
          (let [row (reduce
                     (fn [row j]
                       (let [cost (if (= (nth a (dec i)) (nth b (dec j))) 0 1)
                             d (min (inc (nth prev j))
                                    (inc (peek row))
                                    (+ (nth prev (dec j)) cost))]
                         (conj row
                               (if (and prev2 (> i 1) (> j 1)
                                        (= (nth a (dec i)) (nth b (- j 2)))
                                        (= (nth a (- i 2)) (nth b (dec j))))
                                 (min d (inc (nth prev2 (- j 2))))
                                 d))))
                     [i]
                     (range 1 (inc n)))]
            (recur (inc i) prev row)))))))

;; ── presentation signal ─────────────────────────────────────────────────────

(def presentation-weights
  "Deliberately ordered so that only :inbound-only-spoof and :whole-number-typo clear
  `anchor-threshold` — those are the two that can corroborate OTHER numbers."
  {":inbound-only-spoof" 600
   ":whole-number-typo"  450
   ":prefix-borrow"      300
   ":scrambled"          200})

(def anchor-threshold
  "Minimum presentation score for a number to act as a route-concentration ANCHOR." 450)

(def scramble-max-ratio
  "OSA distance / published-number length ceiling for the weak `:scrambled` signal." 0.3)

(def prefix-min-length
  "Minimum shared leading-digit run to count as `:prefix-borrow`.

  6 digits, not 3: Japanese landline numbers share 2-4 leading digits across whole regions
  (`03` covers all of Tokyo), so a short shared prefix is not evidence of anything. Requiring
  6 means the caller reproduced the institution's exchange as well as its area code.
  Lowering this is the single easiest way to manufacture false positives on ordinary numbers
  in the same city as a ministry, which is why the benign set in the tests pins it."
  6)

(defn- prefix-run
  "Length of the shared leading-digit run between two digit strings."
  [a b]
  (count (take-while true? (map = a b))))

(defn presentation-hit
  "Best institution-impersonation signal for a presented number, or nil. Returns
  {:institution :method :distance :score}.

  `:outbound-able` institution numbers are skipped entirely — an institution that may
  legitimately call out must never be reported as impersonating itself.

  An EXACT match against an `:inbound-only` number is the strongest signal available and is
  the only one that needs no corroboration, because a consultation shortcode cannot be the
  origin of a call: there is nothing to weigh, the presentation is impossible.

  An exact match against a `:published` (not inbound-only) number returns nil — that is the
  institution's real number and this scorer cannot tell a genuine call from a spoof of it.
  Returning nil here is the honest answer, and it is precisely why `lookup`-style callback
  verification (cloud-itonami/meibo) is the control that actually works, not this scorer."
  ([presented] (presentation-hit presented institutions))
  ([presented insts]
   (let [p (digits presented)]
     (when (seq p)
       (->> insts
            (remove #(= :outbound-able (:kind %)))
            (keep (fn [{:keys [institution number kind max-edits]}]
                    (let [n (digits number)
                          d (osa-distance p n)]
                      (cond
                        (and (= p n) (= kind :inbound-only))
                        {:institution institution :method ":inbound-only-spoof" :distance 0
                         :score (presentation-weights ":inbound-only-spoof")}

                        ;; exact match on a non-inbound-only published number: no claim.
                        (= p n) nil

                        (and (pos? max-edits) (<= d max-edits))
                        {:institution institution :method ":whole-number-typo" :distance d
                         :score (presentation-weights ":whole-number-typo")}

                        (and (>= (count n) prefix-min-length)
                             (>= (prefix-run p n) prefix-min-length))
                        {:institution institution :method ":prefix-borrow" :distance d
                         :score (presentation-weights ":prefix-borrow")}

                        (and (>= (count n) prefix-min-length)
                             (<= (/ (double d) (count n)) scramble-max-ratio)
                             (<= (abs (- (count p) (count n))) 2))
                        {:institution institution :method ":scrambled" :distance d
                         :score (presentation-weights ":scrambled")}

                        :else nil))))
            (sort-by (juxt (comp - :score) :distance :institution))
            first)))))

;; ── route concentration ─────────────────────────────────────────────────────

(def route-weights
  "n anchors sharing the route (excluding the number itself) → corroboration score.
  Same ladder as phish_infra's cohost-weights."
  [[5 400] [2 250] [1 120]])

(defn route-score [n-anchors]
  (or (some (fn [[threshold w]] (when (>= n-anchors threshold) w)) route-weights) 0))

(defn infra-tier
  "[presentation-score route-score] → [confidence-permille status].

  Identical table to phish_infra/infra-tier, with the identical two hard rules:

    · `:confirmed` needs an inbound-only spoof, OR a weaker presentation signal CORROBORATED
      by route concentration. Route concentration alone never confirms.
    · A LONE weak presentation signal emits NOTHING ([0 nil]). A shared 6-digit prefix on its
      own is ambiguous, so without route corroboration the observation stays a `:line/*` fact
      with no claim attached.

  `nil` status means NO CLAIM. It does not mean the call is genuine, and nothing in this
  namespace ever asserts that."
  [presentation route]
  (cond
    (and (>= presentation 600) (>= route 250)) [950 ":confirmed"]
    (>= presentation 600)                      [900 ":confirmed"]
    (and (>= presentation 450) (>= route 250)) [900 ":confirmed"]
    (and (>= presentation 450) (pos? route))   [820 ":candidate"]
    (and (>= presentation 200) (>= route 250)) [780 ":candidate"]
    (and (>= presentation 200) (pos? route))   [700 ":candidate"]
    (>= route 400)                             [700 ":candidate"]
    (>= route 250)                             [600 ":candidate"]
    :else                                      [0 nil]))

(defn score-lines
  "Score every line observation. obs = [{\"presented\" \"route\" \"carrier\" \"origin_cc\"
  \"observed\"}] (string-keyed, JSON-shaped like the pdns bridge). `route` is whatever
  procurement handle the feed exposes — SIP trunk, SIM-box id, carrier interconnect,
  originating gateway. Returns a vector sorted by presented number.

  Deterministic and pure: no I/O, no clock, no randomness."
  ([obs] (score-lines obs institutions))
  ([obs insts]
   (let [rows (->> obs (filter #(seq (digits (get % "presented" "")))) vec)
         pres (into {} (map (fn [o] [(get o "presented")
                                     (presentation-hit (get o "presented") insts)]) rows))
         anchors-by-route
         (reduce (fn [m o]
                   (let [r (get o "route")
                         h (pres (get o "presented"))]
                     (if (and r h (>= (:score h) anchor-threshold))
                       (update m r (fnil conj #{}) (get o "presented"))
                       m)))
                 {} rows)]
     (->> rows
          (map (fn [o]
                 (let [num (get o "presented")
                       r (get o "route")
                       h (pres num)
                       p-score (or (:score h) 0)
                       peers (disj (get anchors-by-route r #{}) num)
                       rt (route-score (count peers))
                       [conf status] (infra-tier p-score rt)]
                   {:presented num :route r :carrier (get o "carrier")
                    :origin-cc (get o "origin_cc") :observed (get o "observed")
                    :presentation h :presentation-score p-score
                    :route-anchors (count peers) :route-score rt
                    :score (+ p-score rt) :confidence conf :status status})))
          (sort-by :presented)
          vec))))

;; ── route rollup — where the procurement concentrates ───────────────────────

(defn route-concentration
  "Per-route rollup of scored lines: how many observations, how many anchors, how many reach
  a tier. This is the output that is actually actionable at the infrastructure layer, as
  opposed to the per-number rows, which enumeration can never keep up with (see the ns
  docstring's ~258 new numbers/day figure).

  Reports counts only. It does NOT assert that a route's operator is complicit — that is an
  attribution claim these observations do not support, the same line phish_infra draws by
  refusing to infer `:bulletproof` from \"hosts many phishing domains\"."
  [scored]
  (->> scored
       (filter :route)
       (group-by :route)
       (map (fn [[r rows]]
              {:route r
               :observations (count rows)
               :anchors (count (filter #(>= (:presentation-score %) anchor-threshold) rows))
               :confirmed (count (filter #(= ":confirmed" (:status %)) rows))
               :candidates (count (filter #(= ":candidate" (:status %)) rows))
               :no-claim (count (filter #(nil? (:status %)) rows))
               :carriers (vec (sort (distinct (keep :carrier rows))))}))
       (sort-by (juxt (comp - :confirmed) (comp - :anchors) :route))
       vec))

;; ── bridge → kotoba EAVT rows ───────────────────────────────────────────────

(defn- line-id [n] (str "line." (str/replace (digits n) #"^$" "unknown")))

(defn bridge-line-infra
  "Scored observations → `:line/*` + `:indicator/*` rows.

  Only numbers that reach a tier get an `:indicator/*` row — an unscored observation stays in
  the graph as a `:line/*` fact WITHOUT a claim attached to it. That asymmetry is the whole
  point: absence of an indicator is absence of a claim, never an assertion of legitimacy.

  Emits no PII: a presented number is infrastructure metadata, and no subscriber, victim, or
  device identifier is accepted by this fn or produced by it. (yabai's `:access/*` PII
  envelope discipline, G6/G10, does not apply here because nothing here holds PII to begin
  with — and nothing may be added that does.)"
  ([scored] (bridge-line-infra scored "yabai-line-infra" "authoritative"))
  ([scored source sourcing]
   (let [src (str ":" sourcing)
         lines (mapv (fn [{:keys [presented route carrier origin-cc observed]}]
                       (cond-> (array-map
                                ":line/id" (line-id presented)
                                ":line/presented" presented
                                ":line/sourcing" src)
                         route (assoc ":line/route" route)
                         carrier (assoc ":line/carrier" carrier)
                         origin-cc (assoc ":line/origin-cc" origin-cc)
                         observed (assoc ":line/observed-at" observed)))
                     scored)
         indicators (->> scored
                         (filter :status)
                         (mapv (fn [{:keys [presented presentation presentation-score
                                            route-score confidence status observed]}]
                                 ;; Two DIFFERENT claims, never conflated. With a
                                 ;; presentation hit we can name the impersonated
                                 ;; institution; without one, all we observed is that the
                                 ;; number was procured alongside confirmed spoofs — a real
                                 ;; claim, but a weaker and differently-shaped one, so it
                                 ;; gets its own :indicator/kind and names no institution
                                 ;; rather than guessing which one was being impersonated.
                                 (cond-> (array-map
                                          ":indicator/id" (str "indicator." (digits presented) ".line")
                                          ":indicator/kind" (if presentation
                                                              ":institution-impersonation-line"
                                                              ":line-route-concentration")
                                          ":indicator/line" (line-id presented)
                                          ":indicator/presentation-score" presentation-score
                                          ":indicator/route-score" route-score
                                          ":indicator/confidence-permille" confidence
                                          ":indicator/status" status)
                                   presentation (assoc ":indicator/institution" (:institution presentation)
                                                       ":indicator/method" (:method presentation))
                                   observed (assoc ":indicator/first-seen-at" observed)
                                   true (assoc ":indicator/source" source
                                               ":indicator/sourcing" src)))))]
     {":line" lines ":indicator" indicators})))
