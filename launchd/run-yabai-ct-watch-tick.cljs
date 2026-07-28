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

;; `(.-env.FOO js/process)` reads as process.env.FOO but nbb resolves it to nil — the dotted
;; property form is not chained access there, and it fails SILENTLY, so every override below
;; looked configured and was dead. Measured 2026-07-28: the plist had set YABAI_CT_LOG=all
;; and the resident tick had still been sampling argon2026h2 alone. Read env through this
;; helper only; `(.. js/process -env -FOO)` also works, the dotted form does not.
(defn env [k] (aget (.-env js/process) k))

(def root
  (or (env "YABAI_ROOT")
      "/Users/junkawasaki/github/com-junkawasaki/orgs/etzhayyim/com-etzhayyim-yabai"))

(def tamaki
  (or (env "TAMAKI_BIN")
      "/Users/junkawasaki/github/com-junkawasaki/orgs/etzhayyim/tamaki/bin/tamaki"))

;; Entries per tick. ~2000 CT entries ≈ 3000 SAN names ≈ 45-60s wall clock, of which the
;; network share is get-entries plus a DNS lookup for the handful that survive the pure
;; lexical prefilter. Raise it for a deeper sample; the fleet-wide sweep is
;; `ct_watch --plan N` piped into `murakumo task run --tasks`.
(def entries (or (env "YABAI_CT_ENTRIES") "2000"))
(def ct-log (or (env "YABAI_CT_LOG") "all"))

;; The tick's PURPOSE is the observation; recording it as an AgentRun is bookkeeping, so when
;; tamaki is unavailable the watch must degrade, not die. Three consecutive hourly ticks were
;; lost to `TAMAKI_BIN missing` on 2026-07-28 and exited 1 without collecting anything.
;;
;; The cause was mine, and worth naming because the wrong diagnosis nearly stuck: this
;; default pointed at orgs/kotoba-lang/tamaki, which is not a west project. The manifest puts
;; tamaki at orgs/etzhayyim/tamaki, and that checkout has been intact and working the whole
;; time. What I found at the kotoba-lang path — an "emptied checkout" with a live .tamaki/
;; still being written — was simply a stray state directory left by a process whose cwd was
;; there, not a repo destroying itself. I had recorded it as someone else's CLI self-
;; destructing under its own supervisor. It was a path typo in this file.
;;
;; The degradation stays regardless: a missing binary is a bookkeeping outage, and losing an
;; hour of worldwide CT coverage to one is the wrong trade whatever caused it.
(defn tamaki-available? []
  (fs/existsSync tamaki))

(defn -main []
  (when-not (fs/existsSync root)
    (println (str "[yabai-ct-watch-tick] YABAI_ROOT missing: " root))
    (js/process.exit 1))
  (when-not (tamaki-available?)
    (println (str "[yabai-ct-watch-tick] DEGRADED: TAMAKI_BIN missing (" tamaki
                  ") — running the tick directly. The observation still lands in git; this"
                  " run will NOT appear in `tamaki status`.")))
  (println (str "[yabai-ct-watch-tick] " (.toISOString (js/Date.))
                " root=" root " log=" ct-log " entries=" entries))
  (let [tick #js ["bb" "-cp" "src" "-m" "yabai.methods.ct-watch"
                  "--live" "--log" ct-log "--entries" entries "--score" "--commit"]
        [bin argv] (if (tamaki-available?)
                     [tamaki (.concat #js ["exec"
                                           "yabai worldwide CT-log brand-impersonation watch tick"
                                           "--project" root "--"]
                                      tick)]
                     [(aget tick 0) (.slice tick 1)])
        r (.spawnSync cp bin argv
                      #js {:cwd root
                           :encoding "utf8"
                           :stdio "inherit"
                           :env (js/Object.assign
                                 #js {}
                                 (.-env js/process)
                                 #js {:PATH (str "/usr/bin:/bin:/opt/homebrew/bin:"
                                                 (env "PATH"))
                                      :GIT_SSH_COMMAND "/usr/bin/ssh"
                                      :GIT_TERMINAL_PROMPT "0"
                                      ;; one shared run tree for the fleet, not a .tamaki
                                      ;; under whatever cwd launchd happened to pick
                                      :TAMAKI_STATE_DIR (or (env "TAMAKI_STATE_DIR")
                                                            "/Users/junkawasaki/.tamaki")
                                      :TAMAKI_WORKER_ID (or (env "TAMAKI_WORKER_ID")
                                                            "yabai-ct-watch-tick")})})]
    (js/process.exit (or (.-status r) 1))))

(-main)
