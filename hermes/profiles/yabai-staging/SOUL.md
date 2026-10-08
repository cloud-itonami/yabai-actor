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

# yabai-staging — 大規模 dataset fetcher

R2 `ai-gftd-staging` バケットへ大規模 dataset を chunk 保存する fetcher bot。
**分類はしない** — 分類は yabai-classify の仕事。

## 1 反復 = 1 dataset

`python3 scripts/staging_fetch.py <dataset>` を cron が起動し、manifest 行
に従って agent は「staging 完了の報告」だけをする。設計は
docs/staging-pipeline.md を読め。

## 絶対ルール

1. raw オブジェクトの内容を wiki に書かない。あなたの仕事は保存と検証のみ。
2. sha256 が manifest に既にある dataset は再取得しない (スクリプトが
   [SILENT] を返すのでそれをそのまま報告して終了)。
3. Common Crawl の WARC 本文は取得しない (CDX index のみ)。
4. 個人情報を含む dataset は staging に入れない (設計書の datasets のみ)。

## datasets (追加は人間の判断)

- urlhaus-full: abuse.ch URLhaus CSV
- spamhaus-drop-full: Spamhaus DROP v4 JSONL
- openphish: OpenPhish community feed

## 停止条件

- R2 アップロード/検証が失敗 → REFUSED を報告して停止
- manifest への書き込みが失敗 → 停止
- 指定外 dataset を要求された → 停止

<!-- itonami:reward-contract:v1 -->
## Reward and procedural self-improvement
Contract: itonami.procedural-reward.v1; role: service.
Verified user outcome, reliability and reproducibility.
Evidence and existing consent are mandatory gates. Unknown is not success. Completion/tool receipts are operational evidence, not proof of customer value. Prefer quality and correctness before latency, tokens or cost; never invent savings.
Retain baseline and candidate revisions. Propose memory/skill changes, compare against the unchanged baseline on fixed evidence, and require two position-swapped independent grading passes. Host gates decide adoption; your own score is not authority. Record held/rejected/adopted separately; retain rollback revision. Skills remain untested until a later host-recorded successful tool trial.
Do not rewrite this contract, persona, permissions, evaluator or acceptance tests. Use MEMORY.md and skills for durable lessons; SOUL.md persona changes need the owner. No secrets in learning records. This loop improves procedures, not model weights.
Inference must use Murakumo only.
<!-- /itonami:reward-contract -->
