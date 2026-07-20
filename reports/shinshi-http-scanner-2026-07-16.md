# shinshi.club HTTP vulnerability scanning — 2026-07-16

Status: confirmed observation  
TLP: CLEAR  
Observed: 2026-07-16 UTC  
Published: 2026-07-20  
Source: Cloudflare zone analytics for the operator-owned `shinshi.club` zone

## Summary

On 2026-07-16, `shinshi.club` received an abnormal burst of automated HTTP
reconnaissance. The requests attempted to discover secrets and vulnerable
deployments associated with PHP, WordPress, Rails, Stripe, SendGrid and common
backup/configuration layouts. These resources do not exist on the ClojureScript
Cloudflare Worker application.

The traffic must not be interpreted as audience growth. Cloudflare's aggregate
page-view series included the probes because the single-page application shell
returned HTML for unknown paths. Application telemetry was subsequently changed
to count only known product routes.

## Representative probes

Cloudflare `httpRequestsAdaptiveGroups` showed repeated requests including:

- `/.env.prod`, `/.env.save.2`, `/apps/config/.env`
- `/stripe/webhook_secret.env`, `/stripe-credentials.json`
- `/sendgrid/.env`
- `/rails/info/properties`
- `/config/initializers/twilio.rb`
- `/php-cgi/php-cgi.exe`, `/tests/phpinfo.php`, `/tests/info.php`
- `/wp-admin/css/colors/sunrise/admin.php`, `/admin/php.php`
- `/var/log/apache2/access.log`
- `/backup`

The dominant probing user agent in this slice was `curl/8.7.1`; other probes
spoofed ordinary desktop browsers. Cloudflare Adaptive Analytics is sampled, so
group counts are evidence of relative concentration and are not presented as a
complete raw-log count.

## Assessment

- Category: opportunistic vulnerability scanning / secrets discovery
- Confidence: high for scanner classification
- Targeting confidence: low; paths are generic and consistent with broad
  internet-wide scanning rather than a campaign specifically targeting Shinshi
- Impact observed: analytics pollution and Worker requests
- Compromise evidence: none observed
- Data exposure evidence: none observed

No requested secret, WordPress, PHP or Rails resource existed on the target.
Returning the SPA shell did not disclose the requested files.

## Defensive response

The Shinshi telemetry collector now:

1. counts only known application routes as page views;
2. excludes machine endpoints, static assets and known crawler user agents;
3. separates Cloudflare edge traffic from privacy-preserving product analytics;
4. records acquisition and engagement events without IP addresses or user
   identifiers.

Yabai remains in observe-and-score posture. This report does not authorize an
IP block. Shared hosting, VPN and cloud egress can be reassigned, so enforcement
requires a current observation and separate policy authorization.

## Canonical indicators

The associated source-IP indicators and confidence tiers are published in:

- [`data/http-probe-scanners-kotoba-20260713-20260716.kotoba.edn`](../data/http-probe-scanners-kotoba-20260713-20260716.kotoba.edn)

The earlier Shinshi-specific observation was merged into that deduplicated
Kotoba-native IOC set. Indicators are TLP:CLEAR and contain attack-source IPs,
not victim or account PII.

## Reproduction

The collector and detector are implemented in:

- [`methods/cf_sweep.cljc`](../methods/cf_sweep.cljc)
- [`methods/ingest.cljc`](../methods/ingest.cljc)
- [`methods/test_cf_scanners.cljc`](../methods/test_cf_scanners.cljc)

The public report intentionally omits Cloudflare account tokens, zone
credentials, request headers and any user-related data.
