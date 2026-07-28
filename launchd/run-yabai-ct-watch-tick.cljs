#!/usr/bin/env nbb
;; run-yabai-ct-watch-tick.cljs — LaunchAgent entry for the worldwide phishing watch.
;; One tick of yabai's CT-log supply loop, registered as a tamaki AgentRun:
;;   tamaki exec -> ct_watch/-main -> get-entries -> lexical prefilter -> DNS/ASN ->
;;   phish-infra score -> rebuild-merged! -> git commit/push.
;; Design: ADR-0004 (supply), ADR-0003 (judgement).
;;
;; Why `tamaki exec` and not plain bb: this tick is DETERMINISTIC — no model is in the loop —
;; so it must not be recorded as if kotoba-code ran it. `exec` runs the real argv in
;; --project and emits the same submitted/leased/started/succeeded|failed lifecycle every
;; other AgentRun does, carrying the actual command and exit code, so `tamaki status` shows
;; each tick honestly. Mirrors run-toshokan-patents-tick.cljs / run-innen-tick.cljs.
;;
;; Install: see launchd/com.etzhayyim.yabai.ct-watch-tick.plist in this repo.
(ns run-yabai-ct-watch-tick
  (:require ["node:child_process" :as cp]
            ["node:fs" :as fs]))

(def root
  (or (.-env.YABAI_ROOT js/process)
      "/Users/junkawasaki/github/com-junkawasaki/orgs/etzhayyim/com-etzhayyim-yabai"))

(def tamaki
  (or (.-env.TAMAKI_BIN js/process)
      "/Users/junkawasaki/github/com-junkawasaki/orgs/kotoba-lang/tamaki/bin/tamaki"))

;; Entries per tick. ~2000 CT entries ≈ 3000 SAN names ≈ 45-60s wall clock, of which the
;; network share is get-entries plus a DNS lookup for the handful that survive the pure
;; lexical prefilter. Raise it for a deeper sample; the fleet-wide sweep is
;; `ct_watch --plan N` piped into `murakumo task run --tasks`.
(def entries (or (.-env.YABAI_CT_ENTRIES js/process) "2000"))
(def ct-log (or (.-env.YABAI_CT_LOG js/process) "argon2026h2"))

(defn -main []
  (doseq [[label path] [["YABAI_ROOT" root] ["TAMAKI_BIN" tamaki]]]
    (when-not (fs/existsSync path)
      (println (str "[yabai-ct-watch-tick] " label " missing: " path))
      (js/process.exit 1)))
  (println (str "[yabai-ct-watch-tick] " (.toISOString (js/Date.))
                " root=" root " log=" ct-log " entries=" entries))
  (let [r (.spawnSync cp tamaki
                      #js ["exec"
                           "yabai worldwide CT-log brand-impersonation watch tick"
                           "--project" root
                           "--"
                           "bb" "-cp" "src" "-m" "yabai.methods.ct-watch"
                           "--live" "--log" ct-log "--entries" entries
                           "--score" "--commit"]
                      #js {:cwd root
                           :encoding "utf8"
                           :stdio "inherit"
                           :env (js/Object.assign
                                 #js {}
                                 (.-env js/process)
                                 #js {:PATH (str "/usr/bin:/bin:/opt/homebrew/bin:"
                                                 (.-env.PATH js/process))
                                      :GIT_SSH_COMMAND "/usr/bin/ssh"
                                      :GIT_TERMINAL_PROMPT "0"
                                      ;; one shared run tree for the fleet, not a .tamaki
                                      ;; under whatever cwd launchd happened to pick
                                      :TAMAKI_STATE_DIR (or (.-env.TAMAKI_STATE_DIR js/process)
                                                            "/Users/junkawasaki/.tamaki")
                                      :TAMAKI_WORKER_ID (or (.-env.TAMAKI_WORKER_ID js/process)
                                                            "yabai-ct-watch-tick")})})]
    (js/process.exit (or (.-status r) 1))))

(-main)
