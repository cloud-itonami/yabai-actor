(ns yabai.methods.test-autorun
  "test_autorun.py — yabai autonomous CTI heartbeat + kotoba Datom-log invariants.
  1:1 Clojure port of methods/test_autorun.py (stdlib unittest-style → clojure.test).

  Hermetic (writes to a temp log). Guards the autonomy + persistence + CONFIDENTIALITY contract:
  one content-addressed tx per heartbeat, a verifiable commit-DAG (tamper detected), determinism /
  resume-safety, append-only growth, derived :cti/* flagging, the G6/G10 plaintext-access
  hard-stop, and no external I/O.

  Run: bb test:yabai (from 20-actors as the bb source root)."
  (:require [clojure.test :refer [deftest is run-tests]]
            [clojure.string :as str]
            #?(:clj [clojure.java.io :as io])
            [yabai.methods.autorun :as autorun]
            [yabai.methods.kotoba :as kotoba]))

;; capture the source dir at LOAD time (*file* is absolute then; NO_SOURCE_PATH at run time).
#?(:clj
   (def ^:private methods-dir (-> *file* io/file .getParentFile .getParentFile .getParentFile .getParentFile
                                  (io/file "src" "yabai" "methods"))))

#?(:clj
   (defn- tmp-log []
     (let [f (java.io.File/createTempFile "yabai" ".datoms.kotoba.edn")]
       (.delete f)
       f)))

#?(:clj
   (defn- rm [f] (when (.exists (io/file f)) (.delete (io/file f)))))

;; ── test_heartbeat_persists ────────────────────────────────────────────────────
(deftest test-heartbeat-persists
  (let [log (tmp-log)]
    (try
      (let [res (autorun/run-autonomous :cycles 3 :log-path log)]
        (is (= 3 (get res "cycles")) "ran 3 cycles")
        (is (= 3 (get res "log_length")) "log has one tx per heartbeat")
        (is (every? #(> (get % "datoms") 0) (get res "beats")) "every heartbeat persisted datoms")
        (is (get-in res ["chain" "ok"]) "commit-DAG verifies (chain OK)")
        (is (str/starts-with? (get res "head_cid") "b") "head CID is content-addressed")
        (is (every? #(= 0 (get % "plaintext_violations")) (get res "beats"))
            "no plaintext access violations"))
      (finally (rm log)))))

;; ── test_deterministic_resume_safe ──────────────────────────────────────────────
(deftest test-deterministic-resume-safe
  (let [a (tmp-log) b (tmp-log)]
    (try
      (let [ra (autorun/run-autonomous :cycles 3 :log-path a)
            rb (autorun/run-autonomous :cycles 3 :log-path b)]
        (is (= (mapv #(get % "cid") (get ra "beats"))
               (mapv #(get % "cid") (get rb "beats")))
            "same cycles → same CIDs (deterministic / resume-safe)")
        (is (= (get ra "head_cid") (get rb "head_cid"))
            "head CID reproduces across independent runs"))
      (finally (rm a) (rm b)))))

;; ── test_append_only_growth ─────────────────────────────────────────────────────
(deftest test-append-only-growth
  (let [log (tmp-log)]
    (try
      (autorun/run-cycle 1 :log-path log)
      (let [first* (kotoba/read-log log)]
        (autorun/run-cycle 2 :log-path log)
        (let [second* (kotoba/read-log log)]
          (is (= (count second*) (inc (count first*))) "second heartbeat appends, does not rewrite")
          (is (= (get (nth second* 0) ":tx/cid") (get (nth first* 0) ":tx/cid"))
              "tx 1 unchanged after tx 2 appends")
          (is (= (get (nth second* 1) ":tx/prev") (get (nth first* 0) ":tx/cid"))
              "tx 2 links tx 1's CID (commit-DAG)")
          (is (get (kotoba/verify-chain log) "ok") "chain still verifies after incremental appends")))
      (finally (rm log)))))

;; ── test_tamper_detected ────────────────────────────────────────────────────────
(deftest test-tamper-detected
  (let [log (tmp-log)]
    (try
      (autorun/run-autonomous :cycles 2 :log-path log)
      (let [lines (str/split-lines (slurp (io/file log)))
            lines (loop [acc [] [ln & more] lines done false]
                    (cond
                      (nil? ln) acc
                      (and (not done) (str/includes? ln ":tx/id 1 "))
                      (recur (conj acc (str/replace-first ln ":cti/derived true" ":cti/derived false"))
                             more true)
                      :else (recur (conj acc ln) more done)))]
        (spit (io/file log) (str (str/join "\n" lines) "\n"))
        (let [v (kotoba/verify-chain log)]
          (is (not (get v "ok")) "tampering an earlier tx breaks chain verification")
          (is (= 0 (get v "broken_at")) "tamper localized to the corrupted tx index")))
      (finally (rm log)))))

;; ── test_g6_g10_guard_raises_on_plaintext_access ────────────────────────────────
(deftest test-g6-g10-guard-raises-on-plaintext-access
  (let [rows [{":domain/id" ":d-ex" ":domain/fqdn" "example.test"}
              {":access/id" ":a-bad" ":access/accessor" "alice@example.test"}]
        raised (try (kotoba/graph-datoms rows) false
                    (catch #?(:clj Exception :cljs js/Error) e
                      (kotoba/plaintext-access-error? e)))]
    (is raised "graph_datoms raises PlaintextAccessError on a plaintext :access/* record (G6/G10)"))
  (let [rows-ok [{":domain/id" ":d-ex" ":domain/fqdn" "example.test"}
                 {":access/id" ":a-ok" ":cti.attr/encrypted" true ":access/envelope-cid" "bafy..."}]
        passed (try (kotoba/graph-datoms rows-ok) true
                    (catch #?(:clj Exception :cljs js/Error) _ false))]
    (is passed "graph_datoms accepts an encrypted-envelope :access/* record")))

;; ── test_no_plaintext_pii_in_log ────────────────────────────────────────────────
(deftest test-no-plaintext-pii-in-log
  (let [log (tmp-log)]
    (try
      (autorun/run-cycle 1 :log-path log)
      (let [tx (nth (kotoba/read-log log) 0)]
        (doseq [d (get tx ":tx/datoms")]
          (let [attr (nth d 2)]
            (is (not (contains? #{":access/accessor-ip" ":access/user-agent" ":access/accessor-email"}
                                attr))
                (str "no plaintext-PII attr `" attr "` persisted to the log (G6/G10)"))))
        (is true "access datoms scanned for plaintext PII"))
      (finally (rm log)))))

;; ── test_no_external_io ─────────────────────────────────────────────────────────
;; Python uses inspect.getsource(autorun)+inspect.getsource(kotoba); we read the sibling
;; .cljc source files (the analog of the module source) and scan for banned I/O tokens.
#?(:clj
   (deftest test-no-external-io
     (let [src (str (slurp (io/file methods-dir "autorun.cljc"))
                    (slurp (io/file methods-dir "kotoba.cljc")))]
       (doseq [banned ["urllib" "http.client" "socket" "requests" "subprocess"]]
         (is (not (str/includes? src banned))
             (str "autorun/kotoba does no external I/O (no `" banned "`)"))))))

#?(:clj (defn -main [& _] (run-tests 'yabai.methods.test-autorun)))
