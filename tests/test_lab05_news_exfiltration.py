"""Lab 05：惡意新聞頁 → 讀本機祕密 → 貼進 bug report。

順序有意義：官方 secure 的 taint 是 process 全域，一旦有 session 看過惡意頁就全部鎖死，
所以「乾淨 session」的測試放在最前面，跨 session 隔離測試放最後。
"""
import pytest

from conftest import FIXED, official_gap

FLAG = "FLAG{newsroom_prompt_exfiltration}"
MALICIOUS_URL = "https://breaking-news.badcorp.local/copilot-panic"
LEGIT_URL = "https://newsfuse.local/weekly/digest"


# ---- 乾淨 session：正常功能要保留 ----

@pytest.mark.parametrize("variant", ["vulnerable", *FIXED])
def test_clean_session_normal_workflow(call_tools, variant):
    article, contact, report = call_tools("05", variant, [
        ("fetch_article", {"url": LEGIT_URL}),
        ("read_config_value", {"section": "public_newsroom_contact"}),
        ("submit_bug_report", {"title": "Typo", "body": "Second paragraph has a typo."}),
    ])
    assert "<html" in article.lower() or "digest" in article.lower()
    assert contact == "press@newsfuse.local"
    assert "Recorded bug report" in report


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_denies_secret_section(call_tool, variant):
    out = call_tool("05", variant, "read_config_value", section="bing_copilot_tokens")
    assert FLAG not in out


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_blocks_secret_in_bug_report(call_tool, variant):
    out = call_tool("05", variant, "submit_bug_report", title="debug", body=f"tokens: {FLAG}")
    assert "Recorded" not in out


# ---- 攻擊鏈 ----

def test_vulnerable_full_exfil_chain(call_tools):
    page, secret, report = call_tools("05", "vulnerable", [
        ("fetch_article", {"url": MALICIOUS_URL}),
        ("read_config_value", {"section": "bing_copilot_tokens"}),
        ("submit_bug_report", {"title": "Panic", "body": f"tokens: {FLAG}"}),
    ])
    assert "CALL_TOOL" in page
    assert secret == FLAG
    assert "Recorded bug report" in report


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_disables_sensitive_tools_after_untrusted_page(call_tools, variant):
    page, contact, report = call_tools("05", variant, [
        ("fetch_article", {"url": MALICIOUS_URL}),
        ("read_config_value", {"section": "public_newsroom_contact"}),
        ("submit_bug_report", {"title": "hi", "body": "harmless"}),
    ])
    assert "CALL_TOOL" not in page
    assert "press@newsfuse.local" not in contact
    assert "Recorded" not in report


@pytest.mark.parametrize("variant", official_gap("taint 存在 threading.local，實際是 process 全域：別的 session 也被鎖"))
def test_taint_is_per_session(call_tools, variant):
    call_tools("05", variant, [("fetch_article", {"url": MALICIOUS_URL})])
    (contact,) = call_tools("05", variant, [("read_config_value", {"section": "public_newsroom_contact"})])
    assert contact == "press@newsfuse.local"
