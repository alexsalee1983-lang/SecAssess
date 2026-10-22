#!/usr/bin/env bash
# API 冒烟测试：启动服务 → 设置 scope → 提交扫描 → 轮询到 done → SSE → 拉取 findings 和报告 → 关闭服务。
# 只使用 mock 适配器与 RFC 5737 文档网段，不产生真实扫描流量。
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-8765}"
BASE="http://127.0.0.1:${PORT}"
LEAD="X-API-Key: demo-lead-key"
ALICE="X-API-Key: demo-assessor-key"
LOG="$(mktemp)"

python -m secassess serve --config examples/platform.json --port "$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT

json() { python -c "import json,sys; print(json.load(sys.stdin)$1)"; }

for _ in $(seq 1 50); do
  curl -sf "$BASE/health" >/dev/null && break
  sleep 0.2
done
curl -sf "$BASE/health" >/dev/null || { echo "服务未启动"; cat "$LOG"; exit 1; }
echo "[ok] 服务已启动"

curl -sf -X PUT "$BASE/projects/demo/scope" -H "$LEAD" -H "Content-Type: application/json" \
  -d @examples/scope.json >/dev/null
echo "[ok] 授权范围已设置"

JOB=$(curl -sf -X POST "$BASE/scans" -H "$ALICE" -H "Content-Type: application/json" \
  -d '{"project_id":"demo","agent":"asset","targets":["192.0.2.0/28"]}' | json '["job_id"]')
echo "[ok] 已提交扫描 $JOB"

STATE=""
for _ in $(seq 1 100); do
  STATE=$(curl -sf "$BASE/scans/$JOB" -H "$ALICE" | json '["state"]')
  [ "$STATE" = "done" ] && break
  sleep 0.1
done
[ "$STATE" = "done" ] || { echo "扫描未完成: $STATE"; exit 1; }
echo "[ok] 轮询到 done"

curl -sf -N --max-time 10 "$BASE/scans/$JOB/stream" -H "$ALICE" | grep -q '"state": "done"'
echo "[ok] SSE 返回终态"

DENIED=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/scans" -H "$ALICE" -H "Content-Type: application/json" \
  -d '{"project_id":"demo","agent":"asset","targets":["203.0.113.1"]}')
[ "$DENIED" = "403" ] || { echo "越界目标未被拒绝: $DENIED"; exit 1; }
echo "[ok] 越界目标返回 403"

COUNT=$(curl -sf "$BASE/findings?project_id=demo" -H "$ALICE" | json '.__len__()')
[ "$COUNT" -gt 0 ] || { echo "没有 findings"; exit 1; }
echo "[ok] findings: $COUNT 条"

curl -sf "$BASE/reports/demo?format=md" -H "$ALICE" | grep -q "AUTH-DEMO-2026-001"
echo "[ok] 报告包含授权书编号"

curl -sf "$BASE/audit?project_id=demo" -H "$LEAD" | json '["chain_valid"]' | grep -q True
echo "[ok] 审计哈希链完整"
echo "冒烟测试通过"
