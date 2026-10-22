#!/bin/bash
# 云端会话启动时安装依赖，保证 pytest / ruff / fastapi / httpx 可用。
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"
python3 -m pip install --quiet --disable-pip-version-check -e ".[dev,api,docx]"
