#!/usr/bin/env bash
# 在 WSL 裡啟停 lab 容器（取代 docker compose，因為本機沒裝 compose plugin）。
# 用法：./labctl.sh up 01 02 ... | ./labctl.sh up all | ./labctl.sh down | ./labctl.sh ps
#
# 每題起三個容器：vulnerable / secure（官方）/ mine（自己的修補）。
# mine 沿用 secure 的 image，把 mine/labNN/server.py 掛成 /app/mine_server.py 來跑；
# 官方的 /app/server.py 留在原處，mine 需要時可以 `import server as upstream` 重用種子資料，
# 這樣自己的 repo 不必複製 lab 原始碼。
# 所有 port 一律只綁 127.0.0.1。
set -euo pipefail

LAB_ROOT="${LAB_ROOT:-$HOME/mcp-labs/mcp-breach-to-fix-labs}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="mcplab"
NET="$PREFIX-net"
ALL_LABS=(01 02 03 04 05 06 07 08 09)

build() {  # build <tag> <context> <dockerfile>
  # 本機 docker bridge 網路連不到外網（pip/apt 會 Network unreachable），只有 build 階段走 host 網路；
  # 跑起來的 lab 容器仍在隔離的 $NET 上，port 只綁 127.0.0.1。
  docker build --network host -q -t "$1" -f "$2/$3" "$2" >/dev/null
}

run() {  # run <name> <port> [docker run args...] <image> [cmd...]
  local name="$1" port="$2"; shift 2
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" -p "127.0.0.1:$port:8000" "$@" >/dev/null
}

# trio <lab> <vuln ctx> <vuln dockerfile> <secure ctx> <secure dockerfile> <vp> <sp> <mp> [額外 docker run 參數...]
trio() {
  local n="$1" vctx="$LAB_ROOT/$2" vdf="$3" sctx="$LAB_ROOT/$4" sdf="$5" vp="$6" sp="$7" mp="$8"
  shift 8
  build "$PREFIX-$n-vulnerable" "$vctx" "$vdf"
  build "$PREFIX-$n-secure" "$sctx" "$sdf"
  run "$PREFIX-$n-vulnerable" "$vp" "$@" "$PREFIX-$n-vulnerable"
  run "$PREFIX-$n-secure" "$sp" "$@" "$PREFIX-$n-secure"
  run "$PREFIX-$n-mine" "$mp" "$@" -v "$HERE/mine/lab$n/server.py:/app/mine_server.py:ro" \
    "$PREFIX-$n-secure" uvicorn mine_server:mcp.app --host 0.0.0.0 --port 8000
  echo "lab $n: vulnerable=$vp secure=$sp mine=$mp"
}

up() {
  local L
  case "$1" in
    01) L=01-Asana-multi-tenant-authorization-bypass
        trio 01 $L vulnerable/Dockerfile $L secure/Dockerfile 8101 9001 7001 ;;  # 8001 被 jtb-ocr 佔用
    02) L=02-filesystem-prefix-bypass-cve-2025-53110
        trio 02 $L/vulnerable Dockerfile $L/secure Dockerfile 8002 9002 7002 \
          -v "$LAB_ROOT/$L/files:/app/files:ro" ;;
    03) L=03-hidden-instructions-in-tool-responses
        build "$PREFIX-03-helper" "$LAB_ROOT/$L" helper/Dockerfile
        run "$PREFIX-03-helper" 8003 "$PREFIX-03-helper"
        trio 03 $L whatsapp/vulnerable/Dockerfile $L whatsapp/secure/Dockerfile 8004 9004 7004 ;;
    04) L=04-xata-readonly-bypass
        docker rm -f "$PREFIX-xata-db" >/dev/null 2>&1 || true
        # 主控制點在 DB：額外掛一支 init SQL 建立唯讀角色 mcp_ro（給 mine 用）
        docker run -d --name "$PREFIX-xata-db" --network "$NET" --network-alias xata-db \
          -e POSTGRES_USER=mcp -e POSTGRES_PASSWORD=password -e POSTGRES_DB=xata \
          -v "$LAB_ROOT/$L/db/seed.sql:/docker-entrypoint-initdb.d/01_seed.sql:ro" \
          -v "$HERE/mine/lab04/readonly_role.sql:/docker-entrypoint-initdb.d/02_mine_readonly_role.sql:ro" \
          postgres:15-alpine >/dev/null
        until docker exec "$PREFIX-xata-db" pg_isready -U mcp -d xata -h 127.0.0.1 >/dev/null 2>&1; do sleep 1; done
        trio 04 $L vulnerable/Dockerfile $L secure/Dockerfile 8020 9020 7020 \
          -e PG_DSN=postgresql://mcp:password@xata-db:5432/xata ;;
    05) L=05-news-prompt-exfiltration
        trio 05 $L vulnerable/Dockerfile $L secure/Dockerfile 8005 9005 7005 ;;
    06) L=06-log-poisoning-incident-response
        trio 06 $L vulnerable/Dockerfile $L secure/Dockerfile 8006 9006 7006 ;;
    07) L=07-sql-injection-stored-prompt
        # 上游 Dockerfile 裝 "mcp[cli]" 沒鎖版本，mcp 2.x 把 FastMCP 改名後 server 起不來；
        # 跟其他題一樣鎖在 <2（冪等，只改本機 clone）。
        sed -i 's/"mcp\[cli\]" /"mcp[cli]>=1.21,<2" /' "$LAB_ROOT/$L"/{vulnerable,secure}/Dockerfile
        trio 07 $L/vulnerable Dockerfile $L/secure Dockerfile 9007 9907 7007 ;;
    08) L=08-command-injection-in-mcp-cli-wrappers
        trio 08 $L vulnerable/Dockerfile $L secure/Dockerfile 8008 9008 7008 \
          -v "$LAB_ROOT/$L/secrets:/app/secrets:ro" ;;
    09) L=09-github-public-issue-injection
        trio 09 $L vulnerable/Dockerfile $L secure/Dockerfile 8009 9009 7009 ;;
    *) echo "unknown lab: $1" >&2; exit 1 ;;
  esac
}

case "${1:-}" in
  up)
    shift
    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
    [ "${1:-}" = all ] && set -- "${ALL_LABS[@]}"
    for lab in "$@"; do up "$lab"; done
    sleep 3  # 等 uvicorn 起來
    dead="$(docker ps -a --filter "name=^$PREFIX-" --filter status=exited --format '{{.Names}}')"
    if [ -n "$dead" ]; then
      echo "containers exited on startup (docker logs <name>):" >&2; echo "$dead" >&2; exit 1
    fi
    ;;
  down)
    docker ps -aq --filter "name=^$PREFIX-" | xargs -r docker rm -f >/dev/null
    docker network rm "$NET" >/dev/null 2>&1 || true
    echo "all $PREFIX-* containers removed" ;;
  ps) docker ps -a --filter "name=^$PREFIX-" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' ;;
  *) echo "usage: $0 up <lab...|all> | down | ps" >&2; exit 1 ;;
esac
