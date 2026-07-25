(ns yabai.methods.autorun
  "autorun.py — yabai AUTONOMOUS heartbeat loop on the kotoba Datom log.
  1:1 Clojure port of `methods/autorun.py` (ADR-2605301400 §T3).

  Each heartbeat the actor runs its whole DEFENSIVE CTI pipeline ITSELF, with no human in the
  loop:

    observe (load the OFFLINE merged CTI / passive-DNS graph) → classify
      → G6/G10 GUARD (assert every :access/* record is encrypted — hard-stop on plaintext PII)
      → analyze (fast-flux, hosting concentration, IOC load, IP-movement, cert pivots, …)
      → PERSIST a content-addressed transaction to the append-only kotoba Datom log.

  Deterministic / resume-safe (cycle drives tx-id + as-of → same CIDs on re-run) and append-only.
  NO live CT/PDNS pull, NO live-node push (G7/G8 stay gated). Stdlib only.

  House style: pure orchestration over the sibling yabai.* modules; file I/O behind the kotoba
  module's #?(:clj) edges. The Python argparse `__main__` CLI is omitted (note: it is a thin
  driver over run-autonomous with --cycles/--graph/--log/--fresh)."
  (:require [yabai.methods.analyze :as analyze]
            [yabai.methods.kotoba :as kotoba]
            [yabai.methods.yabai-edn :as edn]))

(def base-as-of 20260608)

#?(:clj
   (def ^:private here (-> *file* clojure.java.io/file .getParentFile)))
#?(:clj
   (def ^:private repo-root (.. here getParentFile getParentFile getParentFile)))
#?(:clj
   (def ^:private data (clojure.java.io/file repo-root "data")))
#?(:clj
   (def merged (clojure.java.io/file data "passive-dns.merged.kotoba.edn")))
#?(:clj
   (def seed (clojure.java.io/file data "seed-passive-dns.kotoba.edn")))
#?(:clj
   (def log-default (clojure.java.io/file data "yabai.datoms.kotoba.edn")))

#?(:clj
   (defn- graph-path* [gp]
     (if gp
       gp
       (if (.exists merged) merged seed))))

#?(:clj
   (defn run-cycle
     "One autonomous heartbeat: observe → G6/G10 guard → analyze → persist a content-addressed
     Datom transaction (graph + derived :cti/* signals). cycle drives tx-id + as-of."
     [cycle & {:keys [graph-path log-path] :or {graph-path nil log-path log-default}}]
     (let [rows (edn/load-edn (graph-path* graph-path))
           _ (kotoba/assert-access-encrypted rows)
           b (edn/classify rows)
           a (analyze/analyze b)
           datoms (into (kotoba/graph-datoms rows) (kotoba/derived-datoms a))
           tx (kotoba/make-tx datoms :tx-id cycle :as-of (+ base-as-of cycle)
                              :prev-cid (kotoba/head-cid log-path))
           cid (kotoba/append-tx tx log-path)]
       {"cycle" cycle
        "domains" (get a "n_domains")
        "pdns" (get a "n_pdns")
        "iocs" (get a "n_ioc")
        "fast_flux" (count (get a "fast_flux"))
        "access_encrypted" (get a "access_encrypted")
        "access_total" (get a "access_total")
        "plaintext_violations" (get a "plaintext_violations")
        "datoms" (count datoms)
        "cid" cid})))

#?(:clj
   (defn run-autonomous
     "Drive `cycles` self-paced heartbeats. Each appends one content-addressed transaction to the
     kotoba Datom log. Returns the run summary + final head CID + chain verification."
     [& {:keys [cycles graph-path log-path] :or {cycles 3 graph-path nil log-path log-default}}]
     (let [beats (mapv #(run-cycle % :graph-path graph-path :log-path log-path)
                       (range 1 (inc cycles)))]
       {"cycles" cycles
        "beats" beats
        "log_length" (count (kotoba/read-log log-path))
        "head_cid" (kotoba/head-cid log-path)
        "chain" (kotoba/verify-chain log-path)})))

#?(:clj
   (defn -main
     "Thin CLI driver over run-autonomous for launchd residency (meisai pattern,
     ADR-2606122400 系). --cycles N (default 1) / --graph PATH / --log PATH / --fresh
     (truncate log first). Prints run summary + head CID; exits (NOT a long-running loop,
     so KeepAlive would be wrong — launchd StartInterval re-sweeps hourly)."
     [& args]
     (let [argmap (apply hash-map args)
           cycles (some-> (get argmap "--cycles") Integer/parseInt)
           graph-path (get argmap "--graph")
           log-path (get argmap "--log")
           fresh? (get argmap "--fresh")]
       (when (and log-path fresh?)
         (spit log-path ""))
       (let [result (run-autonomous :cycles (or cycles 1)
                                    :graph-path graph-path
                                    :log-path (or log-path log-default))]
         (println (pr-str result))
         (shutdown-agents)))))
