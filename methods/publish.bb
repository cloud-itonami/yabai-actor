#!/usr/bin/env kbb
;; yabai self-publish — thin wrapper delegating to the SHARED kototama organism runtime.
(require '[babashka.process :refer [shell]])
(def root (-> *file* (java.io.File.) .getAbsoluteFile .getParentFile .getParentFile))
(def runtime (str root "/../../com-junkawasaki/kototama/lib/actor/publish.bb"))
(apply shell "bb" runtime "--actor" (str root) *command-line-args*)
