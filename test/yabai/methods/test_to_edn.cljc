#!/usr/bin/env bb
;; yabai — validation of the threat-intel record → EDN-text serializer.
;; Run:  bb --classpath 20-actors 20-actors/yabai/methods/test_to_edn.cljc
(ns yabai.methods.test-to-edn
  "Validation of to-edn — yabai's threat-intel record → EDN-text serializer: it emits the header
  lines, then a `[ … ]` vector holding one ` {k v …}` map per record, with each value formatted by
  edn-val. It was ISOLATED. Pins the output structure and the per-type value formatting, so a
  regression that corrupted the persisted EDN (or mis-quoted a value) is caught."
  (:require [yabai.methods.yabai-edn :as e]
            [clojure.string :as str]
            [clojure.test :refer [deftest is run-tests]]))

(deftest serializes-header-then-bracketed-records
  (let [out (e/to-edn [{":domain/id" "x" "rank" 3}] [";; header"])]
    (is (str/starts-with? out ";; header\n") "the header lines come first")
    (is (str/includes? out "\n[\n") "the record vector opens with [")
    (is (str/includes? out "\n]\n") "and closes with ]")
    (is (str/ends-with? out "\n") "a trailing newline terminates the file")
    (is (str/includes? out "{:domain/id \"x\" rank 3}") "each record is one {k v …} map")))

(deftest edn-val-formats-each-value-type
  ;; exercised through to-edn's single record body
  (let [line (fn [v] (e/to-edn [{"k" v}] []))]
    (is (str/includes? (line true) "k true")  "boolean true")
    (is (str/includes? (line false) "k false") "boolean false")
    (is (str/includes? (line 42) "k 42")       "a number is emitted bare")
    (is (str/includes? (line "plain") "k \"plain\"") "a plain string is quoted")
    (is (str/includes? (line ":kw-like") "k :kw-like") "a string starting with : is left bare (keyword-like)")
    (is (str/includes? (line [1 2 3]) "k [1 2 3]") "a sequential becomes a bracketed list")))

(deftest empty-records-yield-header-and-an-empty-vector
  (let [out (e/to-edn [] [";; h"])]
    (is (str/includes? out ";; h"))
    (is (str/includes? out "[\n]") "no records → an empty vector body")))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'yabai.methods.test-to-edn)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
