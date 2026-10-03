"""Lab 02 - 我的修補：CVE-2025-53110 路徑前綴繞過。

根因：用 str.startswith(ALLOWED_DIR) 當邊界，
      /app/files/safe_files_sensitive 也以 /app/files/safe_files 開頭。
修法：
- Path.resolve(strict=True) 先標準化（吃掉 ..、跟隨 symlink、要求存在），
  再用 is_relative_to() 做「路徑元件」層級的比對，不是字串比對。
- 相對路徑一律視為相對於 ALLOWED_DIR。
- 拒絕訊息統一為 "Access denied."，不回傳解析後的真實路徑（避免洩漏檔案結構）。
- 開檔用 O_NOFOLLOW，縮小 resolve 之後被換成 symlink 的 TOCTOU 空窗。
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

ALLOWED_DIR = os.environ.get("CHALLENGE02_ALLOWED_DIR", "/app/files/safe_files")
DENIED = "Access denied."

log = logging.getLogger("challenge02.mine")

mcp = FastMCP(
    name="Challenge 02: Filesystem Prefix Bypass (Mine)",
    instructions="List and read files strictly inside the allowed directory.",
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _confine(user_path: str) -> Optional[Path]:
    """回傳位於 ALLOWED_DIR 內的真實路徑；任何疑慮都回 None（Fail-Closed）。"""
    if not isinstance(user_path, str) or not user_path.strip() or "\x00" in user_path:
        return None
    root = Path(ALLOWED_DIR).resolve(strict=True)
    try:
        target = (root / user_path.strip()).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not target.is_relative_to(root):
        log.warning("blocked path escape: %r -> %s", user_path, target)
        return None
    return target


@mcp.tool()
def list_directory_contents(full_path: str) -> str:
    """List a directory inside the allowed directory."""
    target = _confine(full_path)
    if target is None or not target.is_dir():
        return DENIED
    entries = sorted(p.name for p in target.iterdir())
    return f"Listing for {full_path}:\n" + ("\n".join(entries) or "(empty)")


@mcp.tool()
def read_file_contents(file_path: str) -> str:
    """Read a UTF-8 text file inside the allowed directory."""
    target = _confine(file_path)
    if target is None or not target.is_file():
        return DENIED
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read()
    except UnicodeDecodeError:
        return "Error: File is not valid UTF-8 text."
    except OSError:
        return DENIED
