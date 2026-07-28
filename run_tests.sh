#!/usr/bin/env bash
# yabai — clj/bb test suite (ADR-2606160842 py->clj port wave). Standalone-runnable via babashka
# from the repo root (the actor's namespaces are on the bb classpath); wires the autorun/kotoba
# heartbeat suite into the fleet green-check (was previously unwired).
#
# ADR-0003: runs EVERY method suite, not just autorun. The scanner-bridge, EDN-writer and
# phishing-infra suites existed but were reachable only by invoking each file by hand, so a
# regression in them could not fail the green-check.
set -euo pipefail
cd "$(dirname "$0")"
exec bb -cp src:test -e '
(require (quote clojure.test)
         (quote yabai.methods.test-autorun)
         (quote yabai.methods.test-cf-scanners)
         (quote yabai.methods.test-ct-watch)
         (quote yabai.methods.test-maturity)
         (quote yabai.methods.test-merge-rows)
         (quote yabai.methods.test-line-infra)
         (quote yabai.methods.test-phish-infra)
         (quote yabai.methods.test-to-edn))
(let [r (clojure.test/run-tests (quote yabai.methods.test-autorun)
                                (quote yabai.methods.test-cf-scanners)
                                (quote yabai.methods.test-ct-watch)
                                (quote yabai.methods.test-maturity)
         (quote yabai.methods.test-maturity)
         (quote yabai.methods.test-ct-watch)
         (quote yabai.methods.test-maturity)
                                (quote yabai.methods.test-merge-rows)
                                (quote yabai.methods.test-line-infra)
         (quote yabai.methods.test-phish-infra)
                                (quote yabai.methods.test-to-edn))]
  (System/exit (if (zero? (+ (:fail r) (:error r))) 0 1)))'
