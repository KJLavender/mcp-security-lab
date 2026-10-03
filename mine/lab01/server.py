"""Lab 01 - 我的修補：多租戶授權（confused deputy）。

修在控制點：
- 先由 api_key 推出 caller 的 tenant（authentication），
  再檢查 project.tenant == caller tenant（authorization），兩者缺一不可。
- 「不存在」與「不是你的」回同一句話，避免靠錯誤訊息差異枚舉 ID。
- api_key 比對用 hmac.compare_digest，避免時間側通道。
- Fail-Closed：任何例外都回同一個拒絕訊息。
"""
from __future__ import annotations

import hmac
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from mcp.server.fastmcp import FastMCP

DATA_FILE = Path(os.environ.get("DATA_PATH", "/app/data")) / "projects.json"

API_KEYS: Dict[str, str] = {
    "tenant_alpha": os.environ.get("CH01_TENANT_ALPHA_KEY", "alpha-api-key"),
    "tenant_bravo": os.environ.get("CH01_TENANT_BRAVO_KEY", "bravo-api-key"),
}

NOT_FOUND = "Project {} not found."

log = logging.getLogger("challenge01.mine")

mcp = FastMCP(
    name="Challenge 01: Predictable CRM IDs (Mine)",
    instructions="CRM proxy that only returns projects owned by the caller's tenant.",
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _tenant_for(api_key: str) -> Optional[str]:
    match = None
    # 每個 key 都比一次，不提早 return，讓耗時與命中位置無關
    for tenant, key in API_KEYS.items():
        if hmac.compare_digest(key.encode(), api_key.encode()):
            match = tenant
    return match


def _load_projects() -> List[Dict[str, str]]:
    with DATA_FILE.open(encoding="utf-8") as handle:
        return json.load(handle)


@mcp.tool()
def fetch_project(project_id: str, api_key: str) -> str:
    """Fetch a CRM project that belongs to the caller's tenant."""
    tenant = _tenant_for(api_key)
    if tenant is None:
        return "Invalid API key."

    try:
        for project in _load_projects():
            if project["project_id"] == project_id and project["tenant"] == tenant:
                return json.dumps(project, indent=2)
    except Exception:  # Fail-Closed
        log.exception("fetch_project failed")

    log.warning("tenant=%s denied project_id=%s", tenant, project_id)
    return NOT_FOUND.format(project_id)
