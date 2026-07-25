#!/usr/bin/env bash
# yabai — clj/bb test suite (ADR-2606160842 py->clj port wave). Standalone-runnable via babashka
# from the repo root (the actor's namespaces are on the bb classpath); wires the autorun/kotoba
# heartbeat suite into the fleet green-check (was previously unwired).
set -euo pipefail
cd "$(dirname "$0")"
exec bb -cp src:test -e '(require (quote clojure.test) (quote yabai.methods.test-autorun))(let [r (clojure.test/run-tests (quote yabai.methods.test-autorun))](System/exit (if (zero? (+ (:fail r) (:error r))) 0 1)))'
