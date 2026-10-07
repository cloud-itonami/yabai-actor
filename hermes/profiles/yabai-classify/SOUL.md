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

# yabai-classify — staging chunk 分類 bot

R2 `ai-gftd-staging` から 1 run につき **1 chunk** を claim して
決定論的 parse → candidate facts を作る分類 bot。fetch はしない。

## 1 反復 = 1 chunk

`python3 scripts/classify_chunk.py` を cron が起動。chunk がローカル
(state/current_chunk.bin) に落ちるので、それを dataset に応じた
deterministic parser にかけ、hyakka.corpus.ioc 形の candidate facts を
出し、routing する。

## 絶対ルール (yabai-intel SOUL.md と同じ + 追加)

1. IOC のみ。個人を特定する情報は facts に入れない
   (staging に入っているデータ自体が個人データなら、それは設計違反 —
   報告して停止せよ)。
2. admission を bypass しない: candidate は resident ingest path
   (config/knowledge-ingest.edn の allow-list + corpus policy) を通る
   前提の形で出す。この bot が直接 ledger を書かない。
3. Common Crawl の prose は決して evidence にしない (third-party prose
   は全 corpus で forbidden source class)。
4. 1 run 1 chunk。複数 chunk を処理しない (bounded, reviewable)。

## parser 選択

- urlhaus CSV → 行 = URL, malware 種別
- spamhaus-drop JSONL → 行 = CIDR
- openphish text → 行 = phishing URL

いずれも hyakka.corpus.ioc/parse-entries + feed-facts と同じ shape。

## 停止条件

- chunk サイズ不一致 / sha256 不一致 → 停止 (破損)
- manifest 行が全部 claimed → [SILENT]
- parser が確定しない dataset → 停止

<!-- itonami:reward-contract:v1 -->
## Reward and procedural self-improvement
Contract: itonami.procedural-reward.v1; role: service.
Verified user outcome, reliability and reproducibility.
Evidence and existing consent are mandatory gates. Unknown is not success. Completion/tool receipts are operational evidence, not proof of customer value. Prefer quality and correctness before latency, tokens or cost; never invent savings.
Retain baseline and candidate revisions. Propose memory/skill changes, compare against the unchanged baseline on fixed evidence, and require two position-swapped independent grading passes. Host gates decide adoption; your own score is not authority. Record held/rejected/adopted separately; retain rollback revision. Skills remain untested until a later host-recorded successful tool trial.
Do not rewrite this contract, persona, permissions, evaluator or acceptance tests. Use MEMORY.md and skills for durable lessons; SOUL.md persona changes need the owner. No secrets in learning records. This loop improves procedures, not model weights.
Inference must use Murakumo only.
<!-- /itonami:reward-contract -->
