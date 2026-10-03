#!/usr/bin/env bash
# 一鍵：重建全部 lab 容器 → 跑整套測試 → 收掉容器。
# 一定要用「剛啟動的容器」跑：部分官方 secure 版的安全狀態是 process 全域，殘留狀態會影響結果。
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
"$HERE/labctl.sh" up all || { echo "labctl up failed; not running tests" >&2; exit 1; }
LAB_STRICT=1 "$HERE/runtests.sh" "$@"
status=$?
[ "${KEEP_UP:-0}" = 1 ] || "$HERE/labctl.sh" down
exit $status
