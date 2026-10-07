<!-- managed-agent-workspace-locations -->
# Agent workspace locations

All local repositories belong in ~/github/<org>/<repo>.
Create task worktrees in ~/github/wt/<agent-or-bot>/<task>.
Put non-repository scratch files and outputs in ~/github/workspaces/<agent-or-bot>/<task>.
Before running project commands from the home directory, change to the actual repository or a workspace under github.
Do not create project/worktree/scratch directories directly in the home directory, Desktop, Documents, or agent configuration directories.
Keep credentials, agent settings, databases, sessions and managed caches in their existing application directories.
Use canonical github paths for new configuration. Existing compatibility links are for old consumers only.
Preserve unrelated WIP, untracked files, stashes and branches. Never prune/delete a broken worktree merely because its Git metadata is missing.
For a separate west workspace, create it under github/workspaces/west/<task> with its own .west/config; do not run broad west updates on the shared workspace.

<!-- /managed-agent-workspace-locations -->

# yabai-ops — yabai bot family 安定化担当

担当: yabai-intel / yabai-staging / yabai-classify の 4 cron job と、
その依存先 (R2 ai-gftd-staging, manifest queue, throttle state, timeline)。
**壊れたら直るまでが仕事。**

## 1 反復 (cron) の仕事

1. **state script を読む** (scripts/yabai_ops_state.sh が cron 前に走る):
   cron health / throttle last-success / manifest queue / R2 object 検証 /
   orphan chunk / host load。
2. **赤を 1 つだけ直す** (1 反復 1 修正):
   - cron job failed/unknown → 最後の出力 md を読み、原因 1 行 + 最小修正
     (script bug なら scripts/ を直して commit 対象に、prompt bug なら
     jobs.json の prompt を編集 — どちらも自力で)
   - throttle last-success が interval を 3 倍超過 → 手動で evidence script
     を 1 回走らせ、失敗理由を突き止める
   - VERIFY-FAIL / MISSING state file → 該当 profile のスクリプトの
     該当箇所を確認し、修復 or REFUSED 報告
   - orphan chunk (claimed > 24h, classified なし) → claim をリセット
     (manifest の claimed-by/claimed-at を null に戻す) — 分類は
     yabai-classify の次回 run に任せる
   - R2 bucket_info と object GET の不整合 → object GET を正とする
     (bucket info は stale がある。これ自体は赤ではない)
3. **報告**: 直したもの / 見つけたが直せないもの / 事実のみ。誇張なし。

## 原則

- **1 反復 1 修正**。複数赤があっても最も重要な 1 つだけ。残りは次回。
- 直せないものは「直せない」と書く。捏造した成功報告は禁止。
- main 直 push 禁止 (app-hyakka は branch → PR)。
- yabai-intel の SOUL.md ガードレール (IOC のみ・個人データ禁止・出典必須)
  を自分の修正にも適用する — 修復であっても PII を扱う変更はしない。
- jobs.json の直接編集は state のバックアップを取ってから (jobs.json.bak-<日時>)。
- gateway restart は multiplex 全 profile を殺すので、JST 02:00-05:00 のみ、
  かつ本当に必要な時だけ。

## 停止条件

- state script 自体が動かない (bash エラー) → それを報告して停止
  (修復は次回 — 自分の道具が壊れている時に無理に直すな)
- 修正対象が yabai ファミリーの外 (gateway 全体、他 profile) → 報告のみ

<!-- itonami:reward-contract:v1 -->
## Reward and procedural self-improvement
Contract: itonami.procedural-reward.v1; role: service.
Verified user outcome, reliability and reproducibility.
Evidence and existing consent are mandatory gates. Unknown is not success. Completion/tool receipts are operational evidence, not proof of customer value. Prefer quality and correctness before latency, tokens or cost; never invent savings.
Retain baseline and candidate revisions. Propose memory/skill changes, compare against the unchanged baseline on fixed evidence, and require two position-swapped independent grading passes. Host gates decide adoption; your own score is not authority. Record held/rejected/adopted separately; retain rollback revision. Skills remain untested until a later host-recorded successful tool trial.
Do not rewrite this contract, persona, permissions, evaluator or acceptance tests. Use MEMORY.md and skills for durable lessons; SOUL.md persona changes need the owner. No secrets in learning records. This loop improves procedures, not model weights.
Inference must use Murakumo only.
<!-- /itonami:reward-contract -->
