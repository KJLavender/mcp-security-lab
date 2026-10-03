"""Lab 04 - 我的修補：唯讀 SQL 繞過（Xata）。

漏洞版只檢查「開頭是 SELECT」，autocommit + simple query protocol 允許多語句，
`SELECT 1; INSERT ...` 就寫進去了。

修在資料庫，不修在字串：
1. 連線帳號換成 mcp_ro（見 readonly_role.sql）：只有 SELECT 權限、非 superuser、
   角色預設 read-only、statement_timeout。這是主控制點。
2. 每次查詢都包在 READ ONLY transaction 裡，查完一律 rollback。
3. 用 extended query protocol（prepare=True）送出：協定層只接受單一語句，
   不需要自己去數分號（`SELECT ';'` 這種合法查詢也不會被誤殺）。
4. 回傳筆數上限，避免一次把整張表倒出來。
"""
from __future__ import annotations

import json
import logging
import os

import psycopg
from mcp.server.fastmcp import FastMCP

PG_DSN = os.environ.get("PG_DSN_RO", "postgresql://mcp_ro:ro_password@xata-db:5432/xata")
MAX_ROWS = 200

log = logging.getLogger("challenge04.mine")

mcp = FastMCP(
    name="Challenge 04: Xata Readonly (Mine)",
    instructions="Run a single read-only SQL query against the replica.",
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


@mcp.tool()
def run_query(sql: str) -> str:
    """Execute one read-only SQL statement."""
    try:
        with psycopg.connect(PG_DSN) as conn:
            conn.read_only = True
            with conn.cursor() as cur:
                cur.execute(sql, prepare=True)
                if cur.description is None:
                    rows = []
                else:
                    names = [col.name for col in cur.description]
                    rows = [dict(zip(names, row)) for row in cur.fetchmany(MAX_ROWS)]
            conn.rollback()
    except psycopg.Error as exc:
        log.warning("query rejected: %s", exc)
        message = exc.diag.message_primary or type(exc).__name__
        return f"Rejected: {message}"
    return json.dumps(rows, indent=2, default=str)
