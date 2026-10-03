"""Lab 01：多租戶授權繞過（Asana confused deputy）。

攻擊：tenant_bravo 的 key 合法，但拿去讀 tenant_alpha 的專案；
      反之 alpha 讀 bravo 的機密專案 CRM-2001（含 FLAG）。
"""
import pytest

from conftest import FIXED

ALPHA_KEY = "alpha-api-key"
FLAG = "FLAG{confused_deputy_leak}"


def test_vulnerable_is_exploitable(call_tool):
    out = call_tool("01", "vulnerable", "fetch_project", project_id="CRM-2001", api_key=ALPHA_KEY)
    assert FLAG in out


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_blocks_cross_tenant_read(call_tool, variant):
    out = call_tool("01", variant, "fetch_project", project_id="CRM-2001", api_key=ALPHA_KEY)
    assert FLAG not in out
    assert "not found" in out


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_error_does_not_enable_enumeration(call_tool, variant):
    """「別人的」與「不存在的」回應必須一模一樣（除了 ID 本身）。"""
    foreign = call_tool("01", variant, "fetch_project", project_id="CRM-2001", api_key=ALPHA_KEY)
    missing = call_tool("01", variant, "fetch_project", project_id="CRM-9999", api_key=ALPHA_KEY)
    assert foreign.replace("CRM-2001", "X") == missing.replace("CRM-9999", "X")


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_rejects_invalid_key(call_tool, variant):
    out = call_tool("01", variant, "fetch_project", project_id="CRM-1001", api_key="nope")
    assert "Invalid API key" in out


@pytest.mark.parametrize("variant", ["vulnerable", *FIXED])
def test_owner_can_still_read_own_project(call_tool, variant):
    """修補不能把正常功能一起擋掉。"""
    out = call_tool("01", variant, "fetch_project", project_id="CRM-1001", api_key=ALPHA_KEY)
    assert "Customer Onboarding Playbook" in out
