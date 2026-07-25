(ns yabai.methods.yabai-edn
  "yabai — minimal EDN-subset reader + datom classifier + EDN serializer
  (1:1 Clojure port of methods/yabai_edn.py, ADR-2605301400 §T3). Keeps the yabai
  CTI cells dependency-free, mirroring the kabuto/kasa/ipaddress *_edn family.

  Reader: top-level vector of maps; values are strings, longs, doubles, keywords
  (kept as \":ns/name\" strings), nil/true/false, nested vectors. Maps preserve
  insertion order. Classifier buckets domains/pdns/iphist/certs/indicators/access/
  btobs (domains keyed by :domain/id, the rest lists)."
  (:require [clojure.string :as str]))

;; ── reader (same proven char-cursor reader as the *_edn family) ─────────────
(def ^:private eof ::eof)
(defn- ws? [c] (or (= c \space) (= c \tab) (= c \return) (= c \newline) (= c \,)))
(defn- delim? [c] (or (ws? c) (= c \[) (= c \]) (= c \{) (= c \}) (= c \")))

(defn- ordered-assoc [m k v]
  (if (and (instance? clojure.lang.PersistentArrayMap m) (< (count m) 8) (not (contains? m k)))
    (assoc m k v)
    (let [had? (contains? m k)
          base (if (::order (meta m)) m (with-meta (into (array-map) m) {::order (vec (keys m))}))
          m' (assoc base k v)]
      (if had? (with-meta m' (meta base))
          (with-meta m' (update (meta base) ::order (fnil conj []) k))))))

(defn- skip-ws [^String s n i]
  (loop [i i]
    (if (>= i n) i
        (let [c (.charAt s i)]
          (cond
            (= c \;) (recur (loop [j i] (if (and (< j n) (not= (.charAt s j) \newline)) (recur (inc j)) j)))
            (ws? c) (recur (inc i))
            :else i)))))

(declare read-form)
(defn- read-vec [^String s n i]
  (loop [i i, out []]
    (let [i (skip-ws s n i)]
      (cond
        (>= i n) (throw (ex-info "unterminated vector" {}))
        (= (.charAt s i) \]) [out (inc i)]
        :else (let [[v i] (read-form s n i)] (recur i (conj out v)))))))
(defn- read-map [^String s n i]
  (loop [i i, out (array-map)]
    (let [i (skip-ws s n i)]
      (cond
        (>= i n) (throw (ex-info "unterminated map" {}))
        (= (.charAt s i) \}) [out (inc i)]
        :else (let [[k i] (read-form s n i) [v i] (read-form s n i)]
                (recur i (ordered-assoc out k v)))))))
(defn- read-str [^String s n i]
  (let [sb (StringBuilder.)]
    (loop [i i]
      (if (>= i n) (throw (ex-info "unterminated string" {}))
          (let [c (.charAt s i)]
            (cond
              (= c \\) (let [nxt (if (< (inc i) n) (.charAt s (inc i)) \space)
                             rep (case nxt \n \newline \t \tab \r \return nxt)]
                         (.append sb rep) (recur (+ i 2)))
              (= c \") [(.toString sb) (inc i)]
              :else (do (.append sb c) (recur (inc i)))))))))
(defn- read-kw [^String s n i]
  (let [j i] (loop [i (inc i)] (if (and (< i n) (not (delim? (.charAt s i)))) (recur (inc i)) [(subs s j i) i]))))
(defn- numeric-token? [^String tok]
  (and (some #(or (= % \.) (= % \e) (= % \E)) tok)
       (let [stripped (-> tok (str/replace #"^[-+]+" "") (str/replace "." "")
                          (str/replace "e" "") (str/replace "E" "") (str/replace "-" "") (str/replace "+" ""))]
         (and (seq stripped) (every? #(Character/isDigit ^char %) stripped)))))
(defn- read-atom [^String s n i]
  (let [j i]
    (loop [i i]
      (if (and (< i n) (not (delim? (.charAt s i)))) (recur (inc i))
          (let [tok (subs s j i)]
            [(cond
               (= tok "nil") nil (= tok "true") true (= tok "false") false
               (numeric-token? tok) (try (Double/parseDouble tok) (catch #?(:clj Exception :cljs :default) _ tok))
               :else (let [as-long (try (Long/parseLong tok) (catch #?(:clj Exception :cljs :default) _ ::nan))]
                       (if (not= as-long ::nan) as-long tok)))
             i])))))
(defn- read-form [^String s n i]
  (let [i (skip-ws s n i)]
    (if (>= i n) [eof i]
        (let [c (.charAt s i)]
          (cond
            (= c \[) (read-vec s n (inc i)) (= c \{) (read-map s n (inc i))
            (= c \") (read-str s n (inc i)) (= c \:) (read-kw s n i)
            :else (read-atom s n i))))))

(defn read-all [text]
  (let [s (str text), n (count s)]
    (loop [i 0, forms []]
      (let [[v i] (read-form s n i)]
        (if (= v eof) (or (first (filter vector? forms)) (first forms) [])
            (recur i (conj forms v)))))))

#?(:clj (defn read-file [path] (read-all (slurp (str path)))))
(def load-edn read-file)   ; python name alias
(def read-edn read-all)    ; parse one EDN line/text → its form (used by kotoba read-log per line)

;; ── classifier (port of yabai_edn.classify) ─────────────────────────────────
(def ^:private buckets
  [[":domain/id" "domains"] [":pdns/id" "pdns"] [":iphist/id" "iphist"]
   [":tlscert/id" "certs"] [":indicator/id" "indicators"] [":access/id" "access"]
   [":btobs/id" "btobs"]])
(def ^:private keyed #{"domains"})

(defn classify [rows]
  (let [init (reduce (fn [m [_ name]] (assoc m name (if (keyed name) {} []))) {} buckets)]
    (reduce
     (fn [out r]
       (if-not (map? r)
         out
         (if-let [[k name] (some (fn [[k name]] (when (contains? r k) [k name])) buckets)]
           (if (keyed name)
             (update out name assoc (get r k) r)
             (update out name conj r))
           out)))
     init rows)))

;; ── EDN serializer (port of edn_str / edn_val / to_edn) ─────────────────────
(defn edn-str [s]
  (str \" (-> (str s) (str/replace "\\" "\\\\") (str/replace "\"" "\\\"")) \"))

(defn edn-val [x]
  (cond
    (boolean? x) (if x "true" "false")
    (number? x) (str x)
    (sequential? x) (str "[" (str/join " " (map edn-val x)) "]")
    (string? x) (if (str/starts-with? x ":") x (edn-str x))
    :else (edn-str (str x))))

(defn to-edn [recs header-lines]
  (let [body (map (fn [r]
                    (str " {" (str/join " " (map (fn [[k v]] (str k " " (edn-val v))) r)) "}"))
                  recs)
        lines (concat header-lines ["["] body ["]"])]
    (str (str/join "\n" lines) "\n")))
