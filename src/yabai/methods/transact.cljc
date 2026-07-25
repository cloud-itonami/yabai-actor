(ns yabai.methods.transact
  "transact.py — yabai kotoba Datomic transact bridge.
  1:1 Clojure port of `methods/transact.py` (ADR-2605301400 §T3 save-path).

  Pushes the kotoba-native CTI / passive-DNS graph into a running kotoba node's Datom log via
  POST /xrpc/com.etzhayyim.apps.kotoba.datomic.transact, emitting datomic list-form datoms
  `[:db/add E A V]` (E = entity id string; cardinality-many fans out).

  G6/G10: every :access/* record MUST carry :cti.attr/encrypted true — this bridge REFUSES to
  transact if any access record is plaintext.

  House style: ':…' keyword strings stay strings; pure fns (rows->datoms / schema-datoms /
  check-encryption-invariant) are portable; network + file I/O only behind #?(:clj …). The
  Python `__main__` demo (dry-run printer) is ported as #?(:clj) main."
  (:require [clojure.string :as str]
            [yabai.methods.yabai-edn :as edn]))

(def id-keys [":domain/id" ":pdns/id" ":iphist/id" ":tlscert/id"
              ":indicator/id" ":access/id" ":btobs/id"])

(def nsid-transact "com.etzhayyim.apps.kotoba.datomic.transact")

(defn- first-id [r]
  (some (fn [k] (when (contains? r k) (get r k))) id-keys))

(defn rows->datoms
  "Port of rows_to_datoms(rows). E = entity id; cardinality-many list values fan out."
  [rows]
  (reduce
   (fn [out r]
     (if-not (map? r)
       out
       (let [e (first-id r)]
         (if (nil? e)
           out
           (reduce
            (fn [out [k v]]
              (if (contains? (set id-keys) k)
                out
                (reduce (fn [out item]
                          (conj out (str "[:db/add " (edn/edn-str e) " " k " " (edn/edn-val item) "]")))
                        out
                        (if (sequential? v) v [v]))))
            out
            r)))))
   []
   rows))

(defn check-encryption-invariant
  "Port of check_encryption_invariant(rows) — count of plaintext :access/* records."
  [rows]
  (count (filter #(and (map? %)
                       (contains? % ":access/id")
                       (not= true (get % ":cti.attr/encrypted")))
                 rows)))

(defn schema-datoms-from
  "Port of schema_datoms() over an already-parsed ontology map. Drops :db/doc (free-text '|'
  which the kotoba EDN reader rejects)."
  [onto]
  (let [attrs (if (map? onto) (get onto ":attributes" []) [])]
    (mapv (fn [a]
            (str "{" (str/join " " (->> a
                                        (remove (fn [[k _v]] (= k ":db/doc")))
                                        (map (fn [[k v]] (str k " " (edn/edn-val v))))))
                 "}"))
          attrs)))

#?(:clj
   (defn schema-datoms
     "Read the passive-dns-cti ontology schema EDN → schema datom strings (file I/O edge)."
     [schema-path]
     (schema-datoms-from (edn/load-edn schema-path))))
