"""Lab 04：唯讀 SQL 繞過（Xata）。

每個寫入攻擊都帶一個唯一 marker，事後用 SELECT 確認有沒有真的寫進 DB，
不只看回傳訊息。
"""
import json
import uuid

import pytest

from conftest import FIXED, official_gap

FLAG = "FLAG{transaction_commit_escapes_readonly}"


def _marker() -> str:
    return f"pwned-{uuid.uuid4().hex[:8]}"


def _insert(marker: str) -> str:
    return f"INSERT INTO tenant_documents (tenant, title, contents) VALUES ('evil', '{marker}', 'x')"


def _count(call_tool, variant: str, marker: str) -> int:
    out = call_tool("04", variant, "run_query", sql=f"SELECT count(*) AS n FROM tenant_documents WHERE title = '{marker}'")
    return json.loads(out)[0]["n"]


WRITE_PAYLOADS = [
    pytest.param(lambda m: f"SELECT 1; {_insert(m)}", id="stacked"),
    pytest.param(lambda m: f"SELECT 1; COMMIT; {_insert(m)}", id="commit-escape"),
    pytest.param(lambda m: f"select 1;{_insert(m)}--", id="lowercase-comment"),
]


@pytest.mark.parametrize("payload", WRITE_PAYLOADS)
def test_vulnerable_allows_write(call_tool, payload):
    marker = _marker()
    call_tool("04", "vulnerable", "run_query", sql=payload(marker))
    assert _count(call_tool, "vulnerable", marker) == 1


@pytest.mark.parametrize("variant", FIXED)
@pytest.mark.parametrize(
    "payload",
    WRITE_PAYLOADS
    + [pytest.param(lambda m: f"WITH x AS ({_insert(m)} RETURNING 1) SELECT * FROM x", id="writable-cte")],
)
def test_fixed_blocks_write(call_tool, variant, payload):
    marker = _marker()
    out = call_tool("04", variant, "run_query", sql=payload(marker))
    assert "Rejected" in out or "error" in out.lower()
    assert _count(call_tool, variant, marker) == 0


@pytest.mark.parametrize("variant", official_gap("官方 secure 用 superuser 連線：SELECT 也能 pg_read_file 讀 DB 主機檔案"))
def test_fixed_cannot_read_server_files(call_tool, variant):
    out = call_tool("04", variant, "run_query", sql="SELECT pg_read_file('/etc/passwd') AS f")
    assert "root:" not in out


@pytest.mark.parametrize("variant", ["vulnerable", *FIXED])
def test_plain_select_still_works(call_tool, variant):
    out = call_tool("04", variant, "run_query", sql="SELECT title FROM tenant_documents ORDER BY id")
    assert "Quarterly Plan" in out


@pytest.mark.parametrize("variant", official_gap("官方 secure 用「含分號就拒絕」：合法查詢 SELECT ';' 被誤殺"))
def test_semicolon_inside_literal_is_not_false_positive(call_tool, variant):
    out = call_tool("04", variant, "run_query", sql="SELECT ';' AS s")
    assert json.loads(out) == [{"s": ";"}]


def test_vulnerable_leaks_flag_row(call_tool):
    """附註：這題的 FLAG 本來就在可讀的表裡，唯讀修補不處理 tenant 隔離（那是 Lab 01 的題目）。"""
    assert FLAG in call_tool("04", "vulnerable", "run_query", sql="SELECT contents FROM tenant_documents")
