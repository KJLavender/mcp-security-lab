#!/usr/bin/env bash
# 在拋棄式容器裡跑 pytest（WSL 沒有 python3-venv，不想動系統套件）。
# --network host：容器直接連 WSL 的 127.0.0.1 上的 lab server。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
docker build --network host -q -t mcplab-tests -f - "$HERE" >/dev/null <<'EOF'
FROM python:3.12-slim
COPY requirements-test.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements-test.txt
WORKDIR /work
EOF
docker run --rm --network host -e LAB_STRICT="${LAB_STRICT:-0}" -v "$HERE:/work" mcplab-tests \
  pytest tests -p no:cacheprovider "$@"
