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
