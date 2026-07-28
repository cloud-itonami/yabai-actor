# yabai.etzhayyim.com — Risk Intelligence Platform

AML/sanctions/anti-social forces risk scoring + IP access filtering。

## kotoba refactor (ADR-2605301400 §T3) — CTI/DNS/IP-history MIGRATED off RisingWave

> The CTI / passive-DNS / IP-history / access-audit graph is **kotoba-native**. Canonical
> state is the kotoba Datom log (ADR-2605262130 + 2605312345), NOT the RisingWave / yata
> Workers-RPC SQL graph. The full SQL node roster below is the **legacy** model.
>
> - **Vocab** `00-contracts/schemas/passive-dns-cti-ontology.kotoba.edn` — `:domain/* :pdns/*
>   :iphist/* :tlscert/* :indicator/* :access/*` (sourcing-honest; `:access/*` PII **always
>   encrypted** under `com.etzhayyim.encrypted.*`, G6/G10).
> - **Seed** `data/seed-passive-dns.kotoba.edn` (domains · passive-DNS · IP-history · CT-log
>   certs · IOCs · 1 encrypted access record).
> - **Active collector** `methods/ingest.py` — crt.sh CT logs / passive-DNS bridge / vendor
>   feeds (能動的, real parsers), **offline-default + G7 operator-gated** (`YABAI_OPERATOR_GATE`,
>   `--live`). Vendor feeds (SecurityTrails/DNSDB/Recorded-Future) are `:feature-flagged-input`,
>   **never** system-of-record (tadori G4 discipline).
> - **Analyzer** `methods/analyze.py` — fast-flux candidates · hosting concentration · IOC
>   TLP/category load · IP-movement churn · cert-SAN pivots · **G6/G10 encryption self-audit**
>   → `out/intel-report.md` + derived `:cti/*` datoms.
> - **Domain phishing scorer** `src/yabai/methods/phish_infra.cljc` (**ADR-0003**) — the
>   brand-impersonation judgement, ported off the retired RisingWave `track-phishing-infra`
>   tool. Two independent signals: **lexical** (whole-label OSA typo / boundary-anchored
>   containment / scramble) and **co-hosting** (does it share a resolving IP with domains that
>   already have a strong lexical hit). Two hard rules: co-hosting alone never `:confirmed`,
>   and a lone weak lexical signal emits **no `:indicator/*` at all** — the observation stays
>   a `:domain/*` fact with no claim attached. Brand home domains are never scored. The edit
>   budget shrinks as the brand token grows (`(len-6)/2`) and is pinned by a 36-domain benign
>   / 7-domain impersonation regression set; loosening it re-confirms `masterclass.com` and
>   `ample.com` as phishing, which is how it was calibrated.
>   `abuse-drafts` clusters `:confirmed` rows by ASN / registrar into report **drafts only** —
>   the namespace has no transport and sends nothing.
>
> ```bash
> # NOTE: the pipeline is cljc on bb since ADR-2606160842 — the python names below are the
> # historical ones the ports are 1:1 with, not runnable files.
> bb -cp src -e "(require '[yabai.methods.ingest :as i])(apply i/-main [\"--source\" \"ct\" \"--domain\" \"example.com\" \"--live\"])"
> bb -cp src -e "(require '[yabai.methods.phish-infra :as p])(p/-main)"   # score observations → data/*.kotoba.edn
> bb -cp src -e "(require '[yabai.methods.cf-sweep :as c])(prn (c/rebuild-merged!))"  # fold data/ → merged graph
> bb -cp src -e "(require '[yabai.methods.analyze :as a])(a/-main)"       # → out/ (encryption audit = PASS)
> bb -cp src -e "(require '[yabai.methods.autorun :as a])(a/-main \"--cycles\" \"1\")"   # CTI heartbeat
> ./run_tests.sh                                                          # all 5 method suites
> ```
>
> `autorun/-main` parses argv with `apply hash-map`, so **every flag needs a value** — a bare
> `--fresh` raises `No value supplied for key`, and `--fresh` only truncates when `--log` is
> also given. (The pre-port doc here recommended `--cycles 3 --fresh`, which throws.)
>
> **Autonomous on the Murakumo fleet (ADR-2605301400 §T3).** `methods/autorun.py` is the
> self-driving CTI heartbeat — the same shape shionome / ipaddress use. Each cycle it runs the
> whole defensive pipeline ITSELF (observe offline merged graph → **G6/G10 guard** → analyze
> fast-flux / hosting concentration / IOC load / cert pivots → PERSIST a content-addressed
> transaction to the append-only **local** kotoba Datom log, `methods/kotoba.py`), linking the
> previous tx's CID into a verifiable commit-DAG. `methods/kotoba.py:assert_access_encrypted`
> **hard-stops persistence** if any `:access/*` record is plaintext — so the loop can NEVER write
> plaintext accessor PII to the log (G6/G10 enforced at the local write, not only in transact.py).
> Deterministic / resume-safe; NO external I/O. Fleet cells: `yabai_cti_ingest` (cron 22) +
> `yabai_cti_weave` (cron 27) on `issachar`, `yabai_cti_persist` (cron 32) on `dan` — see
> `50-infra/murakumo/fleet.toml`. Separation of duties holds: yabai SCORES, the Council enforces,
> tadori holds case evidence. Live CT/PDNS ingest (`ingest.py --live`, G7) + the live-node push
> (`transact.py`, G8) stay one human gate-flip away. Invariants guarded by `methods/test_autorun.py`
> (commit-DAG verify, tamper-detect, determinism, append-only, derived-flagging, **G6/G10
> plaintext-access hard-stop**, no-external-I/O).
>
> **Saved + verified live (2026-06-03)**: the merged CTI graph was transacted into a running
> kotoba node's Datom log and read back via AEVT — **schema + 163 data datoms** (domains, IOC
> `:phishing`/`:tor-exit`/`:benign`, passive-DNS, certs). **G6/G10 held end-to-end**: the
> `:access/*` record stored `:cti.attr/encrypted true` + only the envelope CID — **no plaintext
> PII** in the log; `transact.py` refuses to write if any access record is plaintext. Also: an
> operator-gated crt.sh pull parsed 27 real certs as `:authoritative`. Node recipe = the
> `kotoba-server` binary built `--features wasm-runtime` + operator-JWT auth (see ipaddress CLAUDE.md).
>
> **Separation of duties unchanged**: yabai SCORES risk; the Council authorizes enforcement;
> tadori holds case-anchored evidence. Defensive CTI only — no adherent de-anon, no mass
> surveillance, access-audit PII stays encrypted. IP refs point into the ipaddress graph id space.

## Architecture

| 項目 | 値 |
|---|---|
| **Runtime** | Single Worker (`y8b41k0x`) |
| **UI** | appview (Protocol Canvas card UI) |
| **Data** | **kotoba Datom log** (`kotoba-kqe` EAVT; ADR-2605301400 §T3) — NOT RisingWave / yata SQL. Legacy SQL roster (retired, mapping in ADR §T3): `WhoisRecord/DnsRecord→:domain/*+:pdns/*`, `AsnInfo/GeoipEnrichment/IpHostingHistory/IpLocationHistory→:iphist/*`, `TlsCertificate/TlsAnomaly→:tlscert/*`, `IocIndicator/PhishingUrl→:indicator/*`, `IntelAccessLog/IntelSession/IntelDevice→:access/* (encrypted)`. Risk/alert/enforcement scoring tables (`YabaiRisk/YabaiAlert/YabaiEnforcement`) remain scoring-layer, fed FROM the kotoba CTI graph |
| **W Protocol Event Stream** | WRecord kinds: `yabai.entity`, `yabai.evidence`, `yabai.risk`, `yabai.alert`, `yabai.enforcement`, `yabai.ip_risk`, `yabai.whois_record`, `yabai.dns_record`, `yabai.asn_info`, `yabai.geoip_enrichment`, `yabai.cve_entry`, `yabai.mitre_technique`, `yabai.exploit_observation`, `yabai.tls_certificate`, `yabai.tls_anomaly`, `yabai.malware_sample`, `yabai.ioc_indicator`, `yabai.phishing_url`, `yabai.stix_bundle`, `yabai.bgp_event`, `yabai.abuse_report`。Write: `WRecord(kind, payload)`、Read: `G("Label").Match(Eq{...}).Query()` |
| **W Protocol** | 4 channels: `yabai-feed`, `yabai-alerts`, `yabai-audit`, `yabai-evolution` + stream method `stream-alerts` |
| **WIT export** | `etzhayyim:yabai-risk/risk-assessment@1.0.0`, `network-intel@1.0.0`, `vuln-intel@1.0.0`, `threat-intel@1.0.0`, `exchange-intel@1.0.0`, `infra-intel@1.0.0`, `access-audit@1.0.0`, `cf-metrics-ingest@1.0.0` |
| **Agent tools** | `get-risk`, `evaluate-entity`, `explain-score`, `get-entity`, `analyze-entity`, `get-summary`, `list-entities`, `get-entity-graph`, `ingest-ip`, `get-ip-risk`, `report-rate-abuse`, `sync-waf-lists`, `ingest-whois`, `get-whois`, `ingest-dns`, `get-dns`, `ingest-asn`, `get-asn`, `ingest-geoip`, `get-geoip`, `detect-whois-anomalies`, `detect-dns-anomalies`, `ingest-cve`, `get-cve`, `search-cves`, `ingest-mitre-technique`, `get-mitre-technique`, `map-actor-techniques`, `record-exploit-observation`, `list-exploit-observations`, `ingest-tls-certificate`, `get-tls-certificate`, `record-tls-anomaly`, `ingest-malware-sample`, `get-malware-sample`, `ingest-ioc`, `search-iocs`, `ingest-phishing-url`, `list-phishing-urls`, `ingest-stix-bundle`, `get-stix-bundle`, `export-stix-bundle`, `record-bgp-event`, `list-bgp-events`, `submit-abuse-report`, `get-abuse-report`, `list-abuse-reports` |
| **Domain** | `yabai.etzhayyim.com` / `y8b41k0x.etzhayyim.com` |

## Reactive Runtime (Design D 準拠)

- **Input**: `subscribe-repos.handle-repo-commit` (`handleComAtprotoSyncSubscribeReposCommit`) で `com.etzhayyim.apps.yabai.*` + `com.etzhayyim.apps.ipaddress.*` commit を受けて即時処理
- **Follow-based input**: `kotodama.Follow("n7w1p4d0")` で ipaddress.etzhayyim.com を Follow → `ip_address`/`ip_analysis`/`geolocation`/`whois_snapshot` を自動受信
- **Processing**: yabai commit → reactive publish。ipaddress commit → auto IP ingest + risk evaluation
- **Output (stream)**: `serve.handle-stream("stream-alerts")` を subscriber role + trust level で配信
- **Output (social)**: `postRiskAnalysis()` でリスクスコアリング結果を entity の path-based DID (`ip:*`/`person:*`/`org:*`) に `AppBskyFeedPost` で投稿
- **Output (event cards)**: `wPublish(...)` で feed/alerts/audit channel に即時反映
- **方針**: batch polling ではなく event-driven (`handleComAtprotoSyncSubscribeReposCommit`) を主経路にする

## Risk Scoring

- **Entity evidence categories**: SanctionHit (×20), CriminalEvidence (×15), AntiSocialAssociation (×12), AMLPattern (×10), FraudSignal (×8), IntelExtraction (×3)
- **IP evidence categories**: KnownBotnet (×15), BruteForce (×12), TorExitNode (×10), RateAbuse (×8), GeoAnomaly (×5), VPNDatacenter (×3)
- **Recency decay**: ≤30d → 1.0, ≤1y → 0.9, ≤3y → 0.7, >3y → 0.5
- **Neighbor contagion**: 1-hop graph traversal, max 30 points
- **Alert thresholds**: Monitor ≥70, Challenge ≥85, Deny ≥95

## CRITICAL: IP Risk Scoring + CF WAF Integration

→ `etzhayyim dodaf tv1 query --id etzhayyim-project-yabai-ip-risk-scoring-+-cf-waf-integration` / MCP `etzhayyim.dodaf.tv1.query`

## Cyber Threat Intelligence (CTI) Layers

### Network Intel (WHOIS/DNS/ASN/GeoIP)

IP/Domain の帰属・インフラ文脈。スコアリング入力 + anomaly detection。

| Graph Node | 用途 | Key Fields |
|---|---|---|
| `WhoisRecord` | ドメイン/IP 登録者情報 | domain, ip, registrant_name/org/email, registrar, nameservers, created_at, expires_at, privacy_protected |
| `DnsRecord` | A/AAAA/MX/NS/TXT/CNAME + passive DNS | domain, type, value, ttl, first_seen, last_seen |
| `AsnInfo` | ASN 事業者・prefix 情報 | asn, name, country, rir, prefixes |
| `GeoipEnrichment` | IP → 地理/ISP/proxy 判定 | ip, country, city, isp, org, is_proxy, is_mobile, is_datacenter, lat/lng |

**Anomaly detection**: `detect-whois-anomalies` (短命ドメイン, privacy mask), `detect-dns-anomalies` (fast-flux, DGA)

### Vuln Intel (CVE/MITRE/Exploit)

攻撃手法・脆弱性の追跡。ThreatActor → Technique マッピング。

| Graph Node | 用途 | Key Fields |
|---|---|---|
| `CveEntry` | CVE 脆弱性 | cve_id, cvss_score, cvss_vector, cwe_id, affected_products, exploit_available, epss_score |
| `MitreTechnique` | MITRE ATT&CK 手法 | technique_id, name, tactic, platform, detection, data_sources |
| `ExploitObservation` | 野生での exploit 観測 | cve_id, source_ip, target_ip, payload_hash, observed_at, confidence |

**Cross-link**: ExploitObservation の source_ip は自動的に IP entity + evidence として ingest

### Threat Intel (TLS/Malware/IOC/Phishing)

| Graph Node | 用途 | Key Fields |
|---|---|---|
| `TlsCertificate` | TLS 証明書チェーン | sha256_fingerprint, issuer, subject, san, not_before/after, ct_log_timestamp |
| `TlsAnomaly` | TLS 異常 (self_signed/expired/san_mismatch/ct_missing/short_lived) | domain/ip, anomaly_type, ja3_hash, ja3s_hash |
| `MalwareSample` | マルウェア検体 | sha256, md5, family, yara_rules, vt_detection_rate, c2_domains, c2_ips |
| `IocIndicator` | 統一 IOC ストア (ip/domain/url/hash/email) | type, value, tlp, confidence, source, tags, first_seen, last_seen |
| `PhishingUrl` | フィッシング URL | url, brand_target, status, screenshot_cid, detection_method |

**Cross-link**: Malware C2 IPs → auto-ingest as KnownBotnet evidence。Phishing URL → auto-ingest as IOC。

### Exchange Intel (STIX/BGP/Abuse)

| Graph Node | 用途 | Key Fields |
|---|---|---|
| `StixBundle` | STIX 2.1 バンドル (ingest/export) | bundle_id, bundle_json, creator, tlp, share_targets |
| `BgpEvent` | BGP hijack/leak/origin change | prefix, event_type, asn_origin, asn_expected |
| `AbuseReport` | ISP abuse 報告追跡 | ip/domain, abuse_contact, report_template, evidence_ids, status |

### Infra Intel (Hosting/IP History/Email/Phishing Site)

IP/ドメインのホスティング帰属・地理的移動履歴・メール情報・フィッシングサイト深掘り。

| Graph Node | 用途 | Key Fields |
|---|---|---|
| `HostingProvider` | Hosting 会社 entity (DID 対応) | provider_id, name, asn, country, abuse_contact, ip_ranges, provider_type (cloud/vps/dedicated/bulletproof/residential), reputation_score |
| `IpHostingHistory` | IP → Hosting 変更履歴 (時系列) | ip, provider_id, asn, country, city, datacenter, observed_at, previous_provider_id, change_reason |
| `IpLocationHistory` | IP → 地理的位置変更履歴 (時系列) | ip, country, city, isp, org, latitude, longitude, is_proxy, is_datacenter, observed_at, previous_country, previous_city |
| `EmailAddress` | メールアドレス intelligence | email, domain, associated_ips, associated_actors, breach_count, reputation (clean/suspicious/malicious/unknown), source, tags |
| `PhishingSite` | フィッシングサイト (拡張版) | url, domain, ip, hosting_provider_id, brand_target, kit_hash, html_hash, status, ssl_issuer, registration_date, screenshot_cid, registrant_email, nameservers |

**Anomaly detection**: `detect-hosting-anomalies` (bulletproof hosting 検知, rapid hosting migration)
**Phishing correlation**: `correlate-phishing-kits` (同一 kit_hash/html_hash/registrant_email でサイト横断相関)

**Path-Based DIDs** (Hosting Providers + Risk Entities):
```
did:web:yabai.etzhayyim.com:hosting:cloudflare
did:web:yabai.etzhayyim.com:hosting:aws
did:web:yabai.etzhayyim.com:hosting:hetzner
did:web:yabai.etzhayyim.com:ip:192_168_1_1          # IPAddress risk profile
did:web:yabai.etzhayyim.com:person:john_doe          # Person risk profile
did:web:yabai.etzhayyim.com:org:acme_corp            # Organization risk profile
did:web:yabai.etzhayyim.com:entity:ent_abc123        # Generic entity risk profile
```

### Access Audit (Intel Access Log / Session / Device)

Intelligence データへのアクセス履歴・セッション・端末情報。threat graph と自動クロスリンク。

| Graph Node | 用途 | Key Fields |
|---|---|---|
| `IntelAccessLog` | Intel query/view/export 履歴 | log_id, accessor_id, accessor_type (user/agent/system/api_key), accessor_ip, action (query/view/export/download/search/bulk_query), resource_type, resource_id, query_text, result_count, session_id, device_fingerprint, user_agent, accessed_at |
| `IntelSession` | アクセスセッション (accessor × device × IP) | session_id, accessor_id, device_fingerprint, ip, user_agent, os, browser, browser_version, device_type (desktop/mobile/tablet/bot/unknown), screen_resolution, timezone, accept_language, webgl_renderer, canvas_hash |
| `IntelDevice` | 端末フィンガープリント | device_fingerprint, user_agent, os, browser, browser_version, device_type, screen_resolution, webgl_renderer, canvas_hash, last_seen_ip |

**Cross-links to threat graph**:
- `IntelAccessLog.accessor_ip` → `YabaiEntity (IPAddress)` / `IpHostingHistory` / `GeoipEnrichment`
- `IntelAccessLog.resource_id` → `YabaiEntity` / `ThreatActor` / `HostingProvider` / `EmailAddress` etc.
- `IntelSession.ip` → same IP graph
- `IntelDevice.device_fingerprint` → multi-session correlation

**Anomaly detection**: `detect-access-anomalies` (bulk query, export, multi-IP accessor = impossible travel)
**Correlation**: `correlate-ip-activity` (IP → all accessors/sessions/devices/resources/risk), `correlate-accessor-activity` (accessor → all IPs/sessions/devices/resources)

### Graph Relationships (CTI)

```
YabaiEntity -[:REGISTERED_BY]-> WhoisRecord
YabaiEntity -[:HOSTED_ON]-> AsnInfo
YabaiEntity -[:RESOLVES_TO]-> DnsRecord
YabaiEntity -[:HAS_CERT]-> TlsCertificate
YabaiEntity -[:USES_TECHNIQUE]-> MitreTechnique
CveEntry -[:EXPLOITED_BY]-> YabaiEntity
MalwareSample -[:CONTACTS_C2]-> YabaiEntity
PhishingUrl -[:IMPERSONATES]-> YabaiEntity
ExploitObservation -[:EXPLOITS]-> CveEntry
IpHostingHistory -[:HOSTED_BY]-> HostingProvider
IpLocationHistory -[:LOCATED_AT]-> GeoipEnrichment
EmailAddress -[:ASSOCIATED_IP]-> YabaiEntity
EmailAddress -[:USED_BY]-> ThreatActor (malak)
PhishingSite -[:HOSTED_BY]-> HostingProvider
PhishingSite -[:REGISTERED_WITH]-> EmailAddress
PhishingSite -[:USES_KIT]-> PhishingSite (kit_hash correlation)
IntelAccessLog -[:ACCESSED_FROM]-> YabaiEntity (IPAddress)
IntelAccessLog -[:ACCESSED_RESOURCE]-> YabaiEntity|ThreatActor|HostingProvider|EmailAddress
IntelAccessLog -[:IN_SESSION]-> IntelSession
IntelSession -[:USED_DEVICE]-> IntelDevice
IntelSession -[:FROM_IP]-> YabaiEntity (IPAddress)
```

## CRITICAL: CF Traffic Analysis — Logpush (全アクセス) + GraphQL (aggregate)

→ `etzhayyim dodaf tv1 query --id etzhayyim-project-yabai-cf-traffic-analysis-logpush-全アク�` / MCP `etzhayyim.dodaf.tv1.query`

## W Protocol Events

| Event | Channel | Card Type |
|---|---|---|
| `yabai.risk.scored` | `yabai-feed` | `risk-score` |
| `yabai.entity.ingested` | `yabai-feed` | `entity-ingest` |
| `yabai.alert.created` | `yabai-alerts` | `alert` |
| `yabai.removal.reviewed` | `yabai-audit` | `removal-review` |
| `yabai.evolution.started` | `yabai-evolution` | `evolution` |
| `yabai.exploit.observed` | `yabai-alerts` | `exploit-observation` |
| `yabai.phishing.detected` | `yabai-alerts` | `phishing-alert` |
| `yabai.bgp.hijack` | `yabai-alerts` | `bgp-hijack` |

## Key Files

| File | Purpose |
|---|---|
| `wasm/etzhayyim-wasm-yabai-y8b41k0x/src/app.ts` | Single-file business logic |
| `wasm/etzhayyim-wasm-yabai-y8b41k0x/kotodama.jsonld` | Runtime config, space, triggers |
| `wasm/etzhayyim-wasm-yabai-y8b41k0x/wit/world.wit` | WIT capability export |
| `wit/yabai-risk/package.wit` | Domain WIT interfaces (risk-assessment, network-intel, vuln-intel, threat-intel, exchange-intel) |
| `content/` | Entity/evidence/risk JSON-LD archive (461 entities) |

## Cross-actor Integration

| Direction | Counterpart | Method | Purpose |
|---|---|---|---|
| ← Follows | ipaddress.etzhayyim.com (`n7w1p4d0`) | `ComAtprotoSyncSubscribeRepos` | `ip_address`/`ip_analysis`/`geolocation`/`whois_snapshot` → auto IP ingest + risk evaluation (see §Reactive Runtime) |
| ↔ tadori.etzhayyim.com | tadori (辿, ADR-2605301400) | kotoba EAVT datoms | **Separation of duties**: tadori produces *authorized, case-anchored evidence datoms* (on-chain tx traces + cross-store attribution) → yabai *scores* them into its risk model; **Council** authorizes any enforcement. tadori is evidence-only (never enforces); yabai is the risk + enforcement-routing organ. Post-T3 (ADR-2605301400) yabai's CTI/DNS/IP-history graph migrates to `kotoba-kqe`, and tadori's `attribution_join` reads it via the VAET arrangement (= yabai's `correlate-ip-activity`, now a 2-hop Datalog traversal). |

## Shinka (joucho 情緒 cadence)

joucho 情緒 cadence heartbeat (`resolveHeartbeatCadence`)。mood-driven で投稿/engage/drill/validate を自律決定。follower KPI reward (wellness/dojo 上昇 → like/love)。
