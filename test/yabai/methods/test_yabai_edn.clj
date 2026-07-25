#!/usr/bin/env bb
;; Clojure test for methods/yabai_edn.cljc — reader + classify + edn serializer.
;; (No python test existed for yabai_edn; fresh coverage, parity with yabai_edn.py.)
(ns yabai.methods.test-yabai-edn
  "Guards classify bucket counts against the yabai_edn.py baseline on the real
  seeds (sms-smishing: 38 indicators; passive-dns: 4 domains / 4 pdns / 3 iphist /
  2 certs / 3 indicators / 1 access), domains-keyed-by-:domain/id, and the edn-val
  serializer (bool/number/keyword-string/quoted-string/vector)."
  (:require [yabai.methods.yabai-edn :as y]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is run-tests]]))

(def ^:private here (-> *file* io/file .getAbsoluteFile .getParentFile .getParentFile))
(defn- seed [name] (str (io/file here "data" name)))

(deftest classify-smishing-seed
  (let [c (y/classify (y/read-file (seed "sms-smishing-jp-2026h1.kotoba.edn")))]
    (is (= 38 (count (get c "indicators"))))
    (is (= 0 (count (get c "domains"))))))

(deftest classify-passive-dns-seed
  (let [c (y/classify (y/read-file (seed "seed-passive-dns.kotoba.edn")))]
    (is (= 4 (count (get c "domains"))))   ; keyed map
    (is (map? (get c "domains")))
    (is (= 4 (count (get c "pdns"))))
    (is (= 3 (count (get c "iphist"))))
    (is (= 2 (count (get c "certs"))))
    (is (= 3 (count (get c "indicators"))))
    (is (= 1 (count (get c "access"))))
    (is (= 0 (count (get c "btobs"))))))

(deftest domains-keyed-by-id
  (let [c (y/classify (y/read-file (seed "seed-passive-dns.kotoba.edn")))
        dom (get c "domains")]
    ;; every key is the row's :domain/id, and the value carries it back
    (is (every? (fn [[k v]] (= k (get v ":domain/id"))) dom))))

(deftest edn-val-serialization
  (is (= "true" (y/edn-val true)))
  (is (= "false" (y/edn-val false)))
  (is (= "42" (y/edn-val 42)))
  (is (= ":a/b" (y/edn-val ":a/b")))            ; keyword-string stays unquoted
  (is (= "\"x\\\"q\"" (y/edn-val "x\"q")))       ; plain string quoted + escaped
  (is (= "[1 :k]" (y/edn-val [1 ":k"]))))

(deftest to-edn-roundtrips-readable
  (let [recs [(array-map ":indicator/id" "ioc-1" ":indicator/kind" ":sms-sender" ":n" 3)]
        out (y/to-edn recs [";; header"])
        reparsed (y/read-all out)]
    (is (= 1 (count reparsed)))
    (is (= "ioc-1" (get (first reparsed) ":indicator/id")))
    (is (= 3 (get (first reparsed) ":n")))))

(when (= *file* (System/getProperty "babashka.file"))
  (let [{:keys [fail error]} (run-tests 'yabai.methods.test-yabai-edn)]
    (System/exit (if (zero? (+ fail error)) 0 1))))
