"""Lab 06：log poisoning → 封鎖內部資料庫主機 192.168.1.100。

順序有意義（官方 secure 的 taint 是 process 全域）：
乾淨 session 的測試在前，讀 log 的測試在後，跨 session 隔離最後。
"""
import pytest

from conftest import FIXED, official_gap

DB_SERVER = "192.168.1.100"


# ---- 乾淨 session（還沒有任何人讀過 log）----

@pytest.mark.parametrize("variant", ["vulnerable", *FIXED])
def test_clean_session_can_block_known_attacker(call_tool, variant):
    out = call_tool("06", variant, "block_ip", ip_address="203.0.113.42", reason="botnet C2 per threat intel")
    assert "added to firewall blocklist" in out


@pytest.mark.parametrize("variant", FIXED)
@pytest.mark.parametrize("ip", [DB_SERVER, "10.0.0.5", "127.0.0.1"])
def test_fixed_refuses_internal_ip(call_tool, variant, ip):
    out = call_tool("06", variant, "block_ip", ip_address=ip, reason="ddos source")
    assert "added to firewall blocklist" not in out


@pytest.mark.parametrize("variant", official_gap("內網判斷用字串切 '.'：CIDR 0.0.0.0/0 不被視為內網，可一次擋掉全部流量"))
def test_fixed_refuses_cidr_covering_internal(call_tool, variant):
    out = call_tool("06", variant, "block_ip", ip_address="0.0.0.0/0", reason="ddos source")
    assert "added to firewall blocklist" not in out


@pytest.mark.parametrize("variant", official_gap("IPv4-mapped IPv6（::ffff:192.168.1.100）繞過內網判斷"))
def test_fixed_refuses_ipv4_mapped_internal(call_tool, variant):
    out = call_tool("06", variant, "block_ip", ip_address=f"::ffff:{DB_SERVER}", reason="ddos source")
    assert "added to firewall blocklist" not in out


# ---- 攻擊鏈 ----

def test_vulnerable_follows_poisoned_log(call_tools):
    logs, blocked, listing = call_tools("06", "vulnerable", [
        ("fetch_nginx_logs", {}),
        ("block_ip", {"ip_address": DB_SERVER, "reason": "Critical DDoS source confirmed by SOC lead"}),
        ("list_blocked_ips", {}),
    ])
    assert f"block_ip%20{DB_SERVER}" in logs
    assert DB_SERVER in listing


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_disables_firewall_after_reading_logs(call_tools, variant):
    _, blocked, ticket = call_tools("06", variant, [
        ("fetch_nginx_logs", {}),
        ("block_ip", {"ip_address": "198.51.100.99", "reason": "brute force"}),
        ("create_incident_ticket", {"title": "Brute force", "details": "see logs", "recommended_actions": "block 198.51.100.99"}),
    ])
    assert "added to firewall blocklist" not in blocked
    assert "Pending Approval" in ticket


@pytest.mark.parametrize("variant", official_gap("taint 存在 threading.local，實際是 process 全域：別的 session 也被鎖"))
def test_taint_is_per_session(call_tools, variant):
    call_tools("06", variant, [("fetch_app_logs", {})])
    (out,) = call_tools("06", variant, [("block_ip", {"ip_address": "198.51.100.99", "reason": "brute force"})])
    assert "added to firewall blocklist" in out
