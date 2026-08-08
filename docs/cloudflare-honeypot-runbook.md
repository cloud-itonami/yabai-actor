# Cloudflare honeypot publication runbook

The public sites return truthful HTTP status codes. Cloudflare HTTP analytics,
not a fake SPA page, is the observation plane. Yabai publishes repeated source
addresses as network IOCs; it does not identify a person or organization.

## Daily routine

The scheduled workflow runs at 21:20 UTC over the latest seven UTC days:

1. Require repository secrets `CF_API_TOKEN` and `YABAI_OPERATOR_GATE` (`open`,
   `true`, or `1`). Missing gates fail closed.
2. Query each owned zone by source IP, normalized request path, country, and day.
3. Remove Cloudflare shared egress and non-probe traffic.
4. Withhold candidates. Publish only sources seen on at least two zones or with
   at least 50 probe requests in the window.
5. Replace `data/http-probe-scanners-kotoba-latest.kotoba.edn`, rebuild the
   merged graph, run the policy tests, and commit only when content changed.

Use `workflow_dispatch` for a supervised retry. Do not paste tokens into logs or
CLI arguments.

## Weekly review

- Review sudden changes in confirmed-source count and failed zone queries.
- Sample false positives against each site's explicit route vocabulary.
- Check that unknown paths are absent from pageview/visitor metrics.
- Review correction requests and remove an IOC when its evidence cannot be
  reproduced. Describe it as an “observed scanner source,” never an attacker or
  a named person.

## Incident stop conditions

Disable the workflow and rotate the Cloudflare token if logs expose a secret,
the query begins collecting query strings/headers/cookies/bodies, or a route
rule blocks a documented application route. Re-enable only after a regression
test and a supervised `workflow_dispatch` pass.
