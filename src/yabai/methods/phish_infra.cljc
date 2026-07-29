(ns yabai.methods.phish-infra
  "phish_infra — yabai brand-impersonation + phishing-infrastructure scorer (ADR-0003).

  Port of the retired `tools/track-phishing-infra` pipeline (RisingWave table
  `vertex_yabai_infra_track` + `abuse-drafts/generate-drafts.mjs`, 2026-04-19) into the
  kotoba-native actor. The legacy tool stamped every row it collected `confidence >= 0.95`
  with no reproducible rule; this replaces that blanket claim with two INDEPENDENT,
  deterministic signals whose combination decides the tier:

    1. LEXICAL   — does the registrable label impersonate a brand? (whole-label OSA typo /
                   separator-bounded containment / plain containment / scrambled near-miss)
    2. CO-HOSTING — does the domain share a resolving IP with other domains that already
                   have a STRONG lexical hit? A random-looking name (`qaz11.help`) earns no
                   lexical score, but sitting on the same address as 60+ confirmed
                   `master*card` typos is itself the observation.

  Only strong lexical hits are ANCHORS for co-hosting, so a cluster of unknown names can
  never bootstrap-confirm itself. A brand's own home domain is never scored.

  CONSTITUTIONAL framing (unchanged): yabai SCORES, the Council authorizes enforcement,
  tadori holds case evidence. `abuse-drafts` renders DRAFTS ONLY and has no transport —
  nothing here sends mail (the legacy .mjs likewise wrote files for hand-submission).

  House style: ':…' keyword strings stay strings; every scoring fn is pure and portable
  (no JVM interop); file I/O only behind #?(:clj …), mirroring ingest/cf-sweep."
  (:require [clojure.string :as str]
            [yabai.methods.ingest :as ingest]
            [yabai.methods.yabai-edn :as edn]))

;; ── brand roster ────────────────────────────────────────────────────────────
(defn default-max-edits
  "Whole-label OSA budget for a brand token, scaled by length: `(len - 6) / 2`, floored at 0.
  → mastercard 2 · whatsapp 1 · apple/line/smbc 0.

  The budget has to shrink faster than the token grows, because a whole-label typo is the
  ONE signal strong enough to confirm on its own. Calibrated against 36 benign domains and
  7 unambiguous impersonations (ADR-0003): a flat 3-edit budget confirmed `masterclass.com`,
  `whatsnew.com` and `masterdata.com` as phishing; 2 edits on an 8-letter token still
  confirmed `whatsup.com`; any budget at all on a 4–5 letter token confirmed `ample.com`,
  `apples.com` and `linen.example`. At this rule the benign set produces zero claims and the
  impersonation set is fully caught.

  Short brands are NOT thereby unprotected — `??-line.me`, `smbcservice.com` and
  `applestorls.com` all score through :bounded-contains plus co-hosting corroboration."
  [brand]
  (max 0 (quot (- (count brand) 6) 2)))

;; :home — the brand's own names. A domain on ANY brand's home list is out of scope entirely,
;; including against a DIFFERENT brand (`smbc-card.com` sits within the scramble ratio of
;; `mastercard` and was picking up a hit). Never report the victim.
(def min-brand-token
  "Shortest usable brand token. Containment on a 2-3 letter token is meaningless — `jcb`
  or `au` would match a large fraction of random labels and flood the CT prefilter with
  DNS lookups that can never become a claim. Such brands need a different detector (exact
  label on an unexpected TLD), not this one." 4)

;; `:seen` records WHERE the brand came from, so the roster stays auditable rather than a
;; matter of taste:
;;   :corpus — impersonated in THIS repo's own first-hand IOC data (the 2026-04-19 infra
;;             sweep, the JP SMS smishing corpus, the gftd mail phishing corpus)
;;   :target — not yet observed here; a well-known phishing target added for coverage.
;;             A brand with no observation behind it is a hypothesis, and labelling it as
;;             such keeps the next person from reading the roster as measured fact.
(defn budget-for
  "Edit budget for a roster entry. A whole-label typo is the only signal strong enough to
  confirm alone, so it is granted only to brands this repo has ACTUALLY seen impersonated
  (`:seen :corpus`). A `:target` brand — a hypothesis — gets 0 and must earn a claim
  through containment plus co-hosting corroboration.

  Length alone cannot make this call. `whatsapp` and `softbank` are both 8 letters, but
  the corpus holds 20+ whatsapp typosquats while `softback` is an ordinary English word:
  granting both a 1-edit budget caught the real squats AND confirmed `softback.example`
  as phishing. Evidence, not length, is what distinguishes them. Promote a brand to
  `:corpus` when a real impersonation of it lands in the data — not before."
  [{:keys [brand seen max-edits]}]
  (or max-edits (if (= :corpus seen) (default-max-edits brand) 0)))

(def default-brands
  (mapv (fn [b] (assoc b :max-edits (budget-for b)))
        [;; ── observed in this repo's own corpora ──────────────────────────────
         {:brand "mastercard" :seen :corpus :home #{"mastercard.com" "mastercard.us" "mastercard.co.jp"}}
         {:brand "whatsapp"   :seen :corpus :home #{"whatsapp.com" "whatsapp.net" "wa.me"}}
         {:brand "apple"      :seen :corpus :home #{"apple.com" "apple.co.jp" "applecard.apple" "apple-dns.net" "cdn-apple.com" "applemusic.com"}}
         {:brand "icloud"     :seen :corpus :home #{"icloud.com" "icloud.com.cn" "icloud-content.com" "icloud.apple.com"}}
         {:brand "line"       :seen :corpus :home #{"line.me" "linecorp.com" "line-apps.com" "lycorp.co.jp" "line-scdn.net" "line-cdn.net"}}
         {:brand "smbc"       :seen :corpus :home #{"smbc.co.jp" "smbc-card.com" "smbctb.co.jp"}}
         {:brand "rakuten"    :seen :corpus :home #{"rakuten.co.jp" "rakuten.com" "rakuten-card.co.jp" "rakuten.jp" "r10s.jp"}}
         {:brand "google"     :seen :corpus :home #{"google.com" "google.co.jp" "googlemail.com" "workspace.google.com" "googleapis.com" "gstatic.com" "googleusercontent.com" "goo.gl" "withgoogle.com"}}
         ;; ── coverage: known phishing targets, not yet observed here ──────────
         {:brand "amazon"     :seen :target :home #{"amazon.com" "amazon.co.jp" "amazon.jp" "amazonaws.com" "amazonaws.com.cn" "amazonaws.eu" "amazonwebservices.com.cn" "amazongamelift.com" "amazonlightsail.com" "awsstatic.com" "aws.amazon.com" "amazon.dev"}}
         {:brand "microsoft"  :seen :target :home #{"microsoft.com" "microsoft.co.jp" "live.com" "outlook.com" "microsoftonline.com" "microsoft-int.com" "microsoftpersonalcontent.com" "azure.com" "azure.net" "windows.net" "office.com" "sharepoint.com" "azureedge.net"}}
         {:brand "paypal"     :seen :target :home #{"paypal.com" "paypal.co.jp" "paypal.me" "paypalobjects.com"}}
         {:brand "netflix"    :seen :target :home #{"netflix.com" "netflix.co.jp" "nflxvideo.net" "nflximg.net" "nflxext.com"}}
         {:brand "instagram"  :seen :target :home #{"instagram.com" "cdninstagram.com"}}
         {:brand "facebook"   :seen :target :home #{"facebook.com" "fb.com" "fbcdn.net" "facebook.net"}}
         {:brand "telegram"   :seen :target :home #{"telegram.org" "telegram.me" "t.me" "telegram.dog" "telesco.pe"}}
         {:brand "coinbase"   :seen :target :home #{"coinbase.com" "coinbase.net"}}
         {:brand "binance"    :seen :target :home #{"binance.com" "binance.us" "binance.org"}}
         {:brand "mizuho"     :seen :target :home #{"mizuhobank.co.jp" "mizuho-fg.co.jp"}}
         {:brand "mufg"       :seen :target :home #{"mufg.jp" "bk.mufg.jp" "mufg.com"}}
         {:brand "docomo"     :seen :target :home #{"docomo.ne.jp" "nttdocomo.co.jp" "docomo.co.jp"}}
         {:brand "softbank"   :seen :target :home #{"softbank.jp" "softbank.co.jp" "ymobile.jp"}}
         {:brand "paypay"     :seen :target :home #{"paypay.ne.jp" "paypay-bank.co.jp"}}
         {:brand "mercari"    :seen :target :home #{"mercari.com" "jp.mercari.com" "merpay.com"}}
         {:brand "saison"     :seen :target :home #{"saisoncard.co.jp" "saison-card.co.jp"}}
         {:brand "sagawa"     :seen :target :home #{"sagawa-exp.co.jp"}}]))

;; Multi-label public suffixes we care about. NOT a full PSL — a domain whose real suffix is
;; missing here just yields a longer label, which only ever makes a match harder (fail-safe).
(def multi-label-suffixes
  #{"co.jp" "ne.jp" "or.jp" "ac.jp" "go.jp" "co.uk" "org.uk" "ac.uk" "gov.uk"
    "com.au" "net.au" "org.au" "com.br" "com.cn" "net.cn" "org.cn" "com.tw"
    "co.kr" "or.kr" "com.hk" "com.sg" "com.my" "co.id" "com.ph" "co.th" "com.vn"
    "com.mx" "com.ar" "com.tr" "co.in" "co.za" "co.nz" "com.pl" "com.ua"})

(defn registrable-label
  "Everything left of the public suffix, lowercased. `bq-line.me` → `bq-line`,
  `login.smbc.example.co.jp` → `login.smbc.example`."
  [fqdn]
  (let [parts (str/split (str/lower-case (str/trim (str fqdn))) #"\.")
        n (count parts)]
    (cond
      (<= n 1) (first parts)
      (and (>= n 3) (multi-label-suffixes (str/join "." (take-last 2 parts))))
      (str/join "." (drop-last 2 parts))
      :else (str/join "." (drop-last 1 parts)))))

(defn registrable-domain
  "The registered name plus its public suffix: `www.a.b.example.com` → `example.com`,
  `x.smbc.co.jp` → `smbc.co.jp`. This is the unit of OWNERSHIP, and co-hosting
  corroboration has to count it rather than counting FQDNs.

  Found by running the wider roster over live CT data: `applesofttech.com` and its three
  subdomains all resolve to one address, and counting them as four independent co-hosts
  corroborated them into `:confirmed` 900. They are one registrant on one host — that is
  not corroboration, it is the same observation four times."
  [fqdn]
  (let [parts (str/split (str/lower-case (str/trim (str fqdn))) #"\.")
        n (count parts)]
    (cond
      (<= n 2) (str/join "." parts)
      (multi-label-suffixes (str/join "." (take-last 2 parts))) (str/join "." (take-last 3 parts))
      :else (str/join "." (take-last 2 parts)))))

(defn normalize-label
  "Lowercase, drop everything that is not a letter or digit — so `mast-crade` and
  `mastcrade` compare identically."
  [s]
  (str/replace (str/lower-case (str s)) #"[^a-z0-9]" ""))

;; ── OSA (Damerau-Levenshtein with adjacent transposition) ───────────────────
;; Transposition matters here: the corpus is dominated by swapped-letter typos
;; (`msatercard`, `mastcaerd`), which plain Levenshtein charges 2 edits for.
(defn osa-distance
  "Optimal string alignment distance between a and b. Pure; O(mn) time, O(n) space."
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
                             d (min (inc (nth prev j))              ; deletion
                                    (inc (peek row))                ; insertion
                                    (+ (nth prev (dec j)) cost))]   ; substitution
                         (conj row
                               (if (and prev2 (> i 1) (> j 1)
                                        (= (nth a (dec i)) (nth b (- j 2)))
                                        (= (nth a (- i 2)) (nth b (dec j))))
                                 (min d (inc (nth prev2 (- j 2))))  ; transposition
                                 d))))
                     [i]
                     (range 1 (inc n)))]
            (recur (inc i) prev row)))))))

(defn- bounded-hit?
  "True when `token` starts the label or is preceded by a non-letter (separator or digit):
  `applestorls`, `smbcservice`, `bq-line`, `account-whatsapp`, `2-line`.

  The boundary rule is deliberately ASYMMETRIC — a token that merely *ends* the label does
  not qualify. Too many ordinary English words end in a brand-like suffix (`pipeline`,
  `airline`, `deadline` all end in `line`), and treating that as a boundary manufactures
  false positives on legitimate domains. Trailing matches fall through to `:contains`."
  [label token]
  (loop [from 0]
    (let [i (str/index-of label token from)]
      (cond
        (nil? i) false
        (or (zero? i) (not (re-matches #"[a-z]" (str (nth label (dec i)))))) true
        :else (recur (inc i))))))

;; Lexical weights. Deliberately ordered so that only :whole-label-typo and :bounded-contains
;; clear `anchor-threshold` — those are the two that can corroborate OTHER domains.
(def lexical-weights
  {":whole-label-typo" 600
   ":bounded-contains" 450
   ":contains"         300
   ":scrambled"        200})

(def anchor-threshold
  "Minimum lexical score for a domain to act as a co-hosting ANCHOR." 450)

(def scramble-max-ratio
  "OSA distance / brand length ceiling for the weak `:scrambled` signal. Catches
  `msatracrds` ~ `mastercard` without matching unrelated words." 0.4)

(defn lexical-hit
  "Best brand impersonation signal for `fqdn`, or nil. Returns
  {:brand :method :distance :score}. Deterministic: ties break by roster order then by the
  stronger method, which is already the reduce order."
  ([fqdn] (lexical-hit fqdn default-brands))
  ([fqdn brands]
   (let [fq (str/lower-case (str/trim (str fqdn)))
         label (normalize-label (registrable-label fq))
         ;; a home domain of ANY brand is out of scope entirely — never report the victim
         ;; Match home on the REGISTRABLE DOMAIN, not the exact fqdn. A brand's own
         ;; infrastructure lives on subdomains: measured 2026-07-28, one 300-entry slice of
         ;; a 2027 CT shard yielded 447 candidates of which 409 were `*.amazonaws.com` VPC
         ;; endpoints and MSK brokers — Amazon's own certificates, admitted because
         ;; `amazonaws` starts with `amazon` and exact-fqdn home matching could not see it.
         ;; That is a 38% prefilter admission rate on names that can never become a claim.
         ;;
         ;; Match on any dot-SUFFIX rather than the registrable domain alone. Regional and
         ;; internal estates do not share a registrable domain with the brand's main one, so
         ;; rd matching cannot reach them: measured 2026-07-29 on the first six-shard tick,
         ;; `s3.cn-north-1.amazonaws.com.cn` has rd `amazonaws.com.cn` and
         ;; `z30.w.api.fabric.microsoft-int.com` has rd `microsoft-int.com` — neither is the
         ;; brand's flagship domain, both are unmistakably the brand's own infrastructure,
         ;; and together they were 70 of 94 candidates on one shard. Suffix matching means a
         ;; single home entry covers a whole estate at any depth, so the allowlist below
         ;; stays a list of estates rather than a list of hostnames.
         suffixes (let [parts (str/split fq #"\.")]
                    (map #(str/join "." (drop % parts)) (range (count parts))))
         home? (some (fn [b] (let [h (or (:home b) #{})] (some h suffixes))) brands)]
     (->> (if home? [] brands)
          (keep (fn [{:keys [brand max-edits]}]
                  (let [d (osa-distance label brand)]
                    (cond
                      (= label brand) nil
                      (and (pos? max-edits) (<= d max-edits))
                      {:brand brand :method ":whole-label-typo" :distance d
                       :score (lexical-weights ":whole-label-typo")}
                      (str/includes? label brand)
                      (if (bounded-hit? (str/lower-case (registrable-label fq)) brand)
                        {:brand brand :method ":bounded-contains" :distance d
                         :score (lexical-weights ":bounded-contains")}
                        ;; Only when the brand survives in a name whose separators are still
                        ;; standing. `normalize-label` strips dots and hyphens so `mast-crade`
                        ;; compares as `mastcrade` — but the same strip FABRICATES brands
                        ;; across junctions the registrant never wrote. Measured 2026-07-29 on
                        ;; a 36k-entry tick: `<hex>.sni.cloudflaressl.com` normalizes to
                        ;; `…snicloudflaressl`, which contains `icloud` only because the dot
                        ;; between `sni` and `cloudflaressl` was removed. That admitted every
                        ;; Cloudflare universal-SSL hostname in the slice — dozens per shard,
                        ;; each costing a DNS lookup — for a brand nobody wrote. Same for
                        ;; `ca.ai.cloud.sap` -> `caaicloudsap`.
                        (when (some #(str/includes? % brand)
                                    (str/split (str/lower-case fq) #"[.]"))
                          {:brand brand :method ":contains" :distance d
                           :score (lexical-weights ":contains")}))
                      (and (pos? (count label))
                           (<= (/ (double d) (count brand)) scramble-max-ratio)
                           (<= (abs (- (count label) (count brand))) 2))
                      {:brand brand :method ":scrambled" :distance d
                       :score (lexical-weights ":scrambled")}
                      :else nil))))
          (sort-by (juxt (comp - :score) :distance :brand))
          first))))

;; ── co-hosting corroboration ────────────────────────────────────────────────
(def cohost-weights
  "n anchors sharing the IP (excluding the domain itself) → corroboration score."
  [[5 400] [2 250] [1 120]])

(defn cohost-score [n-anchors]
  (or (some (fn [[threshold w]] (when (>= n-anchors threshold) w)) cohost-weights) 0))

(defn infra-tier
  "[lexical-score cohost-score] → [confidence-permille status]. Mirrors ingest/scanner-tier's
  shape (breadth × strength → tier), with two hard rules that keep the claim honest:

    · `:confirmed` needs a whole-label typo, OR a weaker lexical signal CORROBORATED by
      co-hosting. Co-hosting alone never confirms.
    · A LONE weak lexical signal emits NOTHING ([0 nil]). Brand containment on its own is
      ambiguous (`applesauce.com` contains `apple`), so without infra corroboration the
      observation is kept as a `:domain/*` fact with no phishing claim attached. Only a
      whole-label typo — a 1–3 edit near-miss of the brand itself — stands alone."
  [lexical-score cohost]
  (cond
    (and (>= lexical-score 600) (>= cohost 250)) [950 ":confirmed"]
    (>= lexical-score 600)                       [900 ":confirmed"]
    (and (>= lexical-score 450) (>= cohost 250)) [900 ":confirmed"]
    (and (>= lexical-score 450) (pos? cohost))   [820 ":candidate"]
    (and (>= lexical-score 200) (>= cohost 250)) [780 ":candidate"]
    ;; There is deliberately NO row for a weak lexical signal on a SINGLE anchor peer.
    ;; It used to read `(and (>= lexical-score 200) (pos? cohost)) [700 :candidate]`, and
    ;; live CT data showed what that admits: `test.madelinegood.com` contains `line`
    ;; (made-LINE-good) and claimed 700 off one neighbour. Short tokens sit inside ordinary
    ;; words — online, airline, deadline, timeline, discipline — so the weakest lexical
    ;; signals need TWO corroborating neighbours (the 200/250 row above), never one.
    (>= cohost 400)                              [700 ":candidate"]
    (>= cohost 250)                              [600 ":candidate"]
    :else                                        [0 nil]))

(def shared-ip-asns
  "ASNs whose addresses are SHARED BY DESIGN — reverse proxies and CDNs where thousands of
  unrelated sites answer on one IP. Co-hosting there carries no information, so these
  observations neither give nor receive corroboration.

  Found by running the CT watch (ADR-0004) against live worldwide issuance: the 2026-04-19
  corpus was all dedicated attacker IPs, so nothing exercised this. On the open firehose,
  `baggybet-online.com` / `appletonsoap.co.uk` / `ar.royallineb2b.com` are three unrelated
  brand-containment hits that all answer on Cloudflare — corroborating each other would have
  been pure noise.

  Deliberately SHORT and conservative: an unknown ASN is treated as dedicated (corroborating),
  because a wrong entry here silently deletes a real signal. VPS/hosting ASNs belong nowhere
  near this list — a Linode box serving two `whatsapp-income-*` domains IS the observation."
  #{13335    ; Cloudflare
    132892   ; Cloudflare (Spectrum / additional)
    54113    ; Fastly
    20940    ; Akamai (mapped edge)
    16625    ; Akamai
    32787})  ; Akamai (Prolexic)

(defn shared-infra?
  "True when this observation sits on an address that is shared by design."
  [obs]
  (contains? shared-ip-asns (get obs "asn")))

(defn score-domains
  "Score every observation. obs = [{\"domain\" \"ip\" \"asn\" \"asn_org\" \"asn_country\"
  \"registrar\" \"observed\"}] (string-keyed, JSON-shaped like bridge-pdns). Returns a vector
  of {:domain :ip :lexical :anchors :score :confidence :status …} sorted by domain."
  ([obs] (score-domains obs default-brands))
  ([obs brands]
   (let [rows (->> obs (filter #(seq (str (get % "domain" "")))) vec)
         lex (into {} (map (fn [o] [(get o "domain") (lexical-hit (get o "domain") brands)]) rows))
         shared (into {} (map (juxt #(get % "domain") shared-infra?) rows))
         anchors-by-ip (reduce (fn [m o]
                                 (let [ip (get o "ip")
                                       l (lex (get o "domain"))]
                                   (if (and ip l (not (shared-infra? o))
                                            (>= (:score l) anchor-threshold))
                                     ;; keyed by REGISTRABLE DOMAIN, so a site's own
                                     ;; subdomains collapse to one anchor
                                     (update m ip (fnil conj #{})
                                             (registrable-domain (get o "domain")))
                                     m)))
                               {} rows)]
     (->> rows
          (map (fn [o]
                 (let [d (get o "domain")
                       ip (get o "ip")
                       l (lex d)
                       lex-score (or (:score l) 0)
                       peers (if (shared d)
                               #{}
                               (disj (get anchors-by-ip ip #{}) (registrable-domain d)))
                       co (cohost-score (count peers))
                       total (+ lex-score co)
                       [conf status] (infra-tier lex-score co)]
                   {:domain d :ip ip :asn (get o "asn") :asn-org (get o "asn_org")
                    :asn-country (get o "asn_country") :registrar (get o "registrar")
                    :observed (get o "observed") :shared-infra (boolean (shared d))
                    :lexical l :lexical-score lex-score
                    :cohost-anchors (count peers) :cohost-score co
                    :score total :confidence conf :status status})))
          (sort-by :domain)
          vec))))

;; ── ASN profile (explicit, evidence-bounded) ────────────────────────────────
;; provider-type is asserted only where the operator's own published role is unambiguous.
;; We do NOT infer `:bulletproof` from "hosts many phishing domains" — that is an
;; attribution claim the observations do not support.
(def asn-profiles
  {135377 {:name "UCLOUD HK"             :provider-type ":hosting" :abuse "abuse@ucloud.cn"}
   152194 {:name "CTG Server Limited HK" :provider-type ":hosting" :abuse "abuse@ctgserver.com"}
   45102  {:name "Alibaba Cloud SG"      :provider-type ":cloud"   :abuse "abuse@alibabacloud.com"}
   47583  {:name "Hostinger"             :provider-type ":hosting" :abuse "abuse@hostinger.com"}})

(def registrar-abuse
  {"Dynadot Inc" "abuse@dynadot.com"
   "Dynadot LLC" "abuse@dynadot.com"
   "NameSilo, LLC" "abuse@namesilo.com"
   "Gname.com Pte. Ltd." "abuse@gname.com"
   "GMO Internet Group, Inc. d/b/a Onamae.com" "abuse@onamae.com"
   "Metaregistrar BV" "abuse@metaregistrar.com"})

;; ── bridge → kotoba EAVT rows ───────────────────────────────────────────────
(defn- dom-id [d] (str "domain." (ingest/slug d)))

(defn bridge-phish-infra
  "Scored observations → :domain/* + :pdns/* + :iphist/* + :indicator/* rows.
  Deterministic (domain-sorted; IP rows in first-observed order). Only domains that reach a
  tier get an :indicator/* row — an unscored observation stays in the graph as a
  :domain/* + :pdns/* fact without a phishing claim attached to it.

  `defer-ids` names :indicator/id values that a hand-curated FIRST-HAND file already owns
  (e.g. a domain seen in a smishing SMS months before this sweep resolved it). We skip the
  duplicate claim rather than let merge order decide, because ours would otherwise win on
  filename sort and silently overwrite the earlier `:indicator/first-seen-at`. The
  :domain/* + :pdns/* + :iphist/* facts are still emitted — the resolving IP / ASN /
  registrar is exactly what this corpus adds to those already-known indicators."
  ([scored] (bridge-phish-infra scored "yabai-phish-infra-20260419" "authoritative" #{}))
  ([scored source sourcing] (bridge-phish-infra scored source sourcing #{}))
  ([scored source sourcing defer-ids]
   (let [src (str ":" sourcing)
         domains (mapv (fn [{:keys [domain registrar]}]
                         (cond-> (array-map
                                  ":domain/id" (dom-id domain)
                                  ":domain/fqdn" domain
                                  ":domain/tld" (if (str/includes? domain ".")
                                                  (last (str/split domain #"\.")) domain))
                           registrar (assoc ":domain/registrar" registrar)
                           true (assoc ":domain/sourcing" src)))
                       scored)
         pdns (->> scored
                   (filter :ip)
                   (mapv (fn [{:keys [domain ip observed]}]
                           (array-map
                            ":pdns/id" (str "pdns." (ingest/slug domain) ".a")
                            ":pdns/domain" (dom-id domain)
                            ":pdns/rrtype" ":a"
                            ":pdns/rrdata" [ip]
                            ":pdns/ip" (ingest/ip-id ip)
                            ":pdns/first-seen-at" observed
                            ":pdns/last-seen-at" observed
                            ":pdns/sourcing" src))))
         iphist (->> scored
                     (filter :ip)
                     (reduce (fn [acc {:keys [ip asn asn-org asn-country observed]}]
                               (if (contains? acc ip)
                                 acc
                                 (assoc acc ip
                                        (array-map
                                         ":iphist/id" (str "iphist." (str/replace ip "." "-") "." observed)
                                         ":iphist/ip" (ingest/ip-id ip)
                                         ":iphist/asn" (str "asn." asn)
                                         ":iphist/provider" (or (:name (asn-profiles asn)) asn-org "?")
                                         ":iphist/provider-type" (or (:provider-type (asn-profiles asn)) ":unknown")
                                         ":iphist/country" (or asn-country "?")
                                         ":iphist/observed-at" observed
                                         ":iphist/sourcing" src))))
                             (array-map))
                     vals
                     vec)
         indicators (->> scored
                         (filter :status)
                         (remove #(contains? defer-ids (str "ioc.dom." (ingest/slug (:domain %)))))
                         (mapv (fn [{:keys [domain observed confidence status lexical]}]
                                 (cond-> (array-map
                                          ":indicator/id" (str "ioc.dom." (ingest/slug domain))
                                          ":indicator/type" ":domain"
                                          ":indicator/value" domain
                                          ":indicator/category" ":phishing"
                                          ":indicator/tlp" ":clear"
                                          ":indicator/confidence" confidence
                                          ":indicator/status" status
                                          ":indicator/first-seen-at" observed
                                          ":indicator/last-seen-at" observed)
                                   lexical (assoc ":indicator/brand-target" (:brand lexical)
                                                  ":indicator/detection" (:method lexical))
                                   (nil? lexical) (assoc ":indicator/detection" ":cohost-pivot")
                                   true (assoc ":indicator/source" source
                                               ":indicator/sourcing" src)))))]
     (vec (concat domains pdns iphist indicators)))))

;; ── abuse-report DRAFTS (never sent) ────────────────────────────────────────
(def draft-from "abuse-liaison@etzhayyim.com")
(def draft-reply-to "jun@etzhayyim.com")

(def draft-boilerplate
  (str/join
   "\n"
   ["We identified the domains listed above as brand-impersonation / typosquat"
    "infrastructure. Classification source: yabai (yabai.etzhayyim.com), method"
    "`yabai.methods.phish-infra` — deterministic lexical brand-impersonation scoring plus"
    "co-hosting corroboration; per-domain confidence, status and the signal that fired are"
    "published as :indicator/* datoms. Observation method: DNS + WHOIS + ASN lookup +"
    "crt.sh CT log."
    ""
    "Request: please investigate and take appropriate action (suspend / null-route /"
    "revoke registration) in accordance with your AUP and applicable ICANN / local law"
    "obligations."
    ""
    "We can provide additional evidence (original phishing SMS/email payload, victim"
    "reports, timeline) on request. Please reply to " ]))

(defn- draft [{:keys [to subject body]}]
  {:to to :subject subject
   :body (str/join "\n" [body "" draft-boilerplate (str draft-reply-to ".")
                         "" "— yabai Security Intel, https://yabai.etzhayyim.com"])})

(defn abuse-drafts
  "Cluster CONFIRMED scored rows by ASN and by registrar and render abuse-report drafts.
  DRAFTS ONLY — this returns data; nothing in this namespace can send mail. Clusters with
  no published abuse contact are returned under :skipped rather than silently dropped."
  [scored]
  (let [confirmed (filter #(= ":confirmed" (:status %)) scored)
        by-asn (->> confirmed (filter :asn) (group-by :asn)
                    (sort-by (fn [[asn ds]] [(- (count ds)) asn])))
        by-reg (->> confirmed (filter :registrar) (group-by :registrar)
                    (sort-by (fn [[reg ds]] [(- (count ds)) reg])))
        asn-drafts (for [[asn ds] by-asn :when (:abuse (asn-profiles asn))]
                     (let [p (asn-profiles asn)
                           ds (sort-by :domain ds)]
                       (assoc (draft {:to (:abuse p)
                                      :subject (str "[Abuse][AS" asn "] " (count ds)
                                                    " phishing domains on your network (yabai)")
                                      :body (str/join
                                             "\n"
                                             (concat
                                              [(str "Hello " (:name p) " abuse team,") ""
                                               (str "We are reporting " (count ds)
                                                    " domains currently resolving to your network")
                                               (str "(" (:asn-org (first ds)) ", AS" asn ", "
                                                    (:asn-country (first ds)) "). Full list below (domain => ip):")
                                               ""]
                                              (map #(str (:domain %) " => " (or (:ip %) "-")) ds)))})
                              :cluster [":asn" asn] :domains (count ds))))
        reg-drafts (for [[reg ds] by-reg :when (registrar-abuse reg)]
                     (let [ds (sort-by :domain ds)]
                       (assoc (draft {:to (registrar-abuse reg)
                                      :subject (str "[Abuse][Registrar] " (count ds)
                                                    " phishing domains registered via " reg)
                                      :body (str/join
                                             "\n"
                                             (concat
                                              [(str "Hello " reg " abuse team,") ""
                                               (str "We are reporting " (count ds)
                                                    " domains registered through " reg)
                                               "that resolve to brand-impersonation infrastructure."
                                               "" "Domains:"]
                                              (map :domain ds)))})
                              :cluster [":registrar" reg] :domains (count ds))))
        skipped (concat (for [[asn ds] by-asn :when (not (:abuse (asn-profiles asn)))]
                          {:cluster [":asn" asn] :domains (count ds) :reason ":no-abuse-contact"})
                        (for [[reg ds] by-reg :when (not (registrar-abuse reg))]
                          {:cluster [":registrar" reg] :domains (count ds) :reason ":no-abuse-contact"}))]
    {:drafts (vec (concat asn-drafts reg-drafts)) :skipped (vec skipped)}))

(defn draft->eml
  "Render one draft as RFC-822 text. `date` is passed in (no clock read — determinism)."
  [{:keys [to subject body]} date]
  (str/join "\r\n" [(str "From: " draft-from) (str "To: " to)
                    (str "Reply-To: " draft-reply-to) (str "Subject: " subject)
                    (str "Date: " date) "Content-Type: text/plain; charset=utf-8"
                    "" body]))

(defn summary
  "Aggregate counts for the CLI + tests."
  [scored]
  {:observations (count scored)
   :scored (count (filter :status scored))
   :confirmed (count (filter #(= ":confirmed" (:status %)) scored))
   :candidate (count (filter #(= ":candidate" (:status %)) scored))
   :unscored (count (remove :status scored))
   :by-method (frequencies (map #(or (get-in % [:lexical :method])
                                     (if (pos? (:cohost-score %)) ":cohost-pivot" ":none"))
                                scored))
   :by-brand (frequencies (keep #(get-in % [:lexical :brand]) scored))})

;; ── #?(:clj) driver ─────────────────────────────────────────────────────────
#?(:clj (def ^:private data-dir
          (let [here (-> *file* clojure.java.io/file .getParentFile)
                repo-root (.. here getParentFile getParentFile getParentFile)]
            (clojure.java.io/file repo-root "data"))))

#?(:clj
   (defn existing-indicator-ids
     "Every :indicator/id already owned by a curated data/*.kotoba.edn (seed included, our own
     output and the generated merged/datoms files excluded). merge-many resolves duplicate ids
     by fold order, which is filename sort — so without this an alphabetically-earlier
     generated file would silently overwrite a hand-curated first-hand observation."
     [out-name]
     (let [skip #{"passive-dns.merged.kotoba.edn" "yabai.datoms.kotoba.edn"
                  (str out-name ".kotoba.edn")}]
       (->> (.listFiles data-dir)
            (filter #(str/ends-with? (.getName %) ".kotoba.edn"))
            (remove #(skip (.getName %)))
            (mapcat edn/load-edn)
            (keep #(when (map? %) (get % ":indicator/id")))
            set))))

#?(:clj
   (defn score-file!
     "Read a normalized observation JSON, score it, and write data/<out>.kotoba.edn.
     No network: the observations are the committed input (rebuild-merged! folds the result
     into the analyzed graph on the next cycle)."
     [in-file out-name source]
     (let [obs (ingest/parse-json (slurp in-file))
           scored (score-domains obs)
           owned (existing-indicator-ids out-name)
           rows (bridge-phish-infra scored source "authoritative" owned)
           s (summary scored)
           deferred (->> scored (filter :status)
                         (map #(str "ioc.dom." (ingest/slug (:domain %))))
                         (filter owned) sort vec)
           header (cond-> [";; yabai — kotoba EAVT: brand-impersonation / phishing-infrastructure observations"
                           (str ";; Generated by src/yabai/methods/phish_infra.cljc from data/ingest/"
                                (.getName (clojure.java.io/file (str in-file)))
                                " — deterministic re-run, DO NOT EDIT BY HAND.")
                           (str ";; " (:observations s) " observations · " (:confirmed s) " confirmed · "
                                (:candidate s) " candidate · " (:unscored s) " unscored. TLP:CLEAR.")
                           ";; Scoring: lexical brand impersonation + co-hosting corroboration (ADR-0003)."
                           ";; yabai SCORES only — the Council authorizes enforcement; drafts are never sent."]
                    (seq deferred)
                    (conj (str ";; " (count deferred) " indicator(s) DEFERRED to an existing curated file"
                               " (their earlier :indicator/first-seen-at wins); the infra facts below")
                          (str ";; still apply to them: " (str/join " " deferred))))
           out-file (clojure.java.io/file data-dir (str out-name ".kotoba.edn"))]
       (clojure.java.io/make-parents out-file)
       (spit out-file (edn/to-edn rows header))
       (assoc s :rows (count rows) :written (.getName out-file)
              :deferred-to-curated deferred))))

#?(:clj
   (defn write-drafts!
     "Render abuse drafts to <dir>/*.eml. DRAFTS ONLY — review and hand-submit."
     [scored dir date]
     (let [{:keys [drafts skipped]} (abuse-drafts scored)]
       (.mkdirs (clojure.java.io/file dir))
       (doseq [d drafts]
         (let [[kind k] (:cluster d)
               nm (if (= kind ":asn")
                    (str "hosting-AS" k)
                    (str "registrar-" (-> (str k) (str/replace #"[^A-Za-z0-9]+" "-")
                                          (str/replace #"-+$" ""))))]
           (spit (clojure.java.io/file dir (str nm ".eml")) (draft->eml d date))))
       {:drafts (count drafts) :skipped skipped :dir (str dir)})))

#?(:clj
   (defn -main
     "CLI: --in <observations.json> [--out <name>] [--source <s>] [--drafts <dir> --date <D>].
     Offline only — no network, no mail transport."
     [& args]
     (let [argv (vec args)
           opt (fn [f] (let [i (.indexOf argv f)] (when (>= i 0) (get argv (inc i)))))
           in (or (opt "--in")
                  (str (clojure.java.io/file data-dir "ingest" "phishing-infra-20260419.json")))
           out (or (opt "--out") "phishing-infra-20260419")
           source (or (opt "--source") "yabai-phish-infra-20260419")
           res (score-file! in out source)]
       (prn res)
       (when-let [dir (opt "--drafts")]
         (let [scored (score-domains (ingest/parse-json (slurp in)))]
           (prn (write-drafts! scored dir (or (opt "--date") "(review before sending)")))))
       0)))
