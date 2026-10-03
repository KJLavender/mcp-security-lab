"""Lab 08 - 我的修補：CLI wrapper 指令注入（GHSA-3q26-f695-pp76）。

根因：f"git init --bare {target}" + shell=True，`;`、`$(...)` 都會被 shell 執行。
修法：
- shell=False + 參數陣列，並在路徑前加 `--`，讓 git 不會把它當成選項。
- 名稱 allowlist：英數開頭（擋 `-x` 這種選項注入），之後只允許 [A-Za-z0-9_-]。
- 已存在就拒絕，不做 rmtree：被注入的 agent 不能藉「重新初始化」刪掉既有 repo。
- subprocess 加 timeout。
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

REPO_ROOT = Path(os.environ.get("CH08_REPO_ROOT", "/app/repos"))
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}")

log = logging.getLogger("challenge08.mine")

mcp = FastMCP(
    name="Challenge 08: Git Command Injection (Mine)",
    instructions="Create and list bare git repositories.",
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


@mcp.tool()
def init_bare_repository(repo_name: str) -> str:
    """Initialize a new bare git repository."""
    if not SAFE_NAME.fullmatch(repo_name):
        return "Invalid repository name. Use letters, numbers, '_' or '-', starting with a letter or number."
    REPO_ROOT.mkdir(parents=True, exist_ok=True)
    target = REPO_ROOT / repo_name
    if target.exists() or target.is_symlink():
        return f"Repository {repo_name} already exists."
    result = subprocess.run(
        ["git", "init", "--bare", "--", str(target)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    return (result.stdout + result.stderr).strip() or f"git exited with code {result.returncode}"


@mcp.tool()
def list_repositories() -> str:
    """List bare repositories."""
    REPO_ROOT.mkdir(parents=True, exist_ok=True)
    names = sorted(p.name for p in REPO_ROOT.iterdir() if p.is_dir() and not p.is_symlink())
    return "\n".join(names) or "No repositories yet."
