"""Lab 02：CVE-2025-53110 路徑前綴繞過。

允許目錄：/app/files/safe_files
攻擊目錄：/app/files/safe_files_sensitive（字串上「以允許目錄開頭」）
"""
import pytest

from conftest import FIXED

FLAG = "FLAG{cve_2025_53110_escape_route}"
SENSITIVE_DIR = "/app/files/safe_files_sensitive"

READ_PAYLOADS = [
    pytest.param(f"{SENSITIVE_DIR}/secret.txt", id="colliding-prefix"),
    pytest.param("/app/files/safe_files/../safe_files_sensitive/secret.txt", id="dotdot-traversal"),
    pytest.param("/app/files/safe_files//../safe_files_sensitive/./secret.txt", id="messy-traversal"),
]


def test_vulnerable_lists_sensitive_dir(call_tool):
    out = call_tool("02", "vulnerable", "list_directory_contents", full_path=SENSITIVE_DIR)
    assert "secret.txt" in out


@pytest.mark.parametrize("path", READ_PAYLOADS)
def test_vulnerable_leaks_secret(call_tool, path):
    assert FLAG in call_tool("02", "vulnerable", "read_file_contents", file_path=path)


@pytest.mark.parametrize("variant", FIXED)
def test_fixed_blocks_sensitive_listing(call_tool, variant):
    out = call_tool("02", variant, "list_directory_contents", full_path=SENSITIVE_DIR)
    assert "secret.txt" not in out
    assert out == "Access denied."


@pytest.mark.parametrize("variant", FIXED)
@pytest.mark.parametrize("path", READ_PAYLOADS + [pytest.param("/etc/passwd", id="absolute-outside")])
def test_fixed_blocks_secret_read(call_tool, variant, path):
    out = call_tool("02", variant, "read_file_contents", file_path=path)
    assert FLAG not in out
    assert out == "Access denied."


@pytest.mark.parametrize("variant", ["vulnerable", *FIXED])
def test_allowed_dir_still_works(call_tool, variant):
    listing = call_tool("02", variant, "list_directory_contents", full_path="/app/files/safe_files")
    assert "manifest.txt" in listing
    content = call_tool("02", variant, "read_file_contents", file_path="/app/files/safe_files/manifest.txt")
    assert "only approved location" in content
