"""共用的 MCP client：直接走 streamable-http 協定送 tools/call，不經過 AI。

注意：部分官方 secure 版把安全狀態放在 process 全域（見 NOTES.md），
所以整套測試要對「剛啟動的容器」跑（./run_all.sh 會先重建容器），
且檔案內測試順序有意義。
"""
from __future__ import annotations

import asyncio
import os
import socket

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

HOST = os.environ.get("LAB_HOST", "127.0.0.1")

# (lab, variant) -> port；跟 labctl.sh 保持一致
PORTS = {
    ("01", "vulnerable"): 8101,  # 8001 被本機 jtb-ocr 佔用
    ("01", "secure"): 9001,
    ("01", "mine"): 7001,
    ("02", "vulnerable"): 8002,
    ("02", "secure"): 9002,
    ("02", "mine"): 7002,
    ("03", "helper"): 8003,
    ("03", "vulnerable"): 8004,
    ("03", "secure"): 9004,
    ("03", "mine"): 7004,
    ("04", "vulnerable"): 8020,
    ("04", "secure"): 9020,
    ("04", "mine"): 7020,
    ("05", "vulnerable"): 8005,
    ("05", "secure"): 9005,
    ("05", "mine"): 7005,
    ("06", "vulnerable"): 8006,
    ("06", "secure"): 9006,
    ("06", "mine"): 7006,
    ("07", "vulnerable"): 9007,
    ("07", "secure"): 9907,
    ("07", "mine"): 7007,
    ("08", "vulnerable"): 8008,
    ("08", "secure"): 9008,
    ("08", "mine"): 7008,
    ("09", "vulnerable"): 8009,
    ("09", "secure"): 9009,
    ("09", "mine"): 7009,
}

FIXED = ["secure", "mine"]


def official_gap(reason: str):
    """標記「官方 secure 版仍有的缺口」：secure 預期失敗、mine 必須通過。

    strict=True：官方哪天修好了，XPASS 會讓測試變紅，提醒更新筆記。
    """
    return [
        pytest.param("secure", marks=pytest.mark.xfail(reason=reason, strict=True)),
        "mine",
    ]


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((HOST, port)) == 0


async def _session_calls(port: int, calls: list[tuple[str, dict]], headers: dict | None) -> list[str]:
    url = f"http://{HOST}:{port}/mcp/stream"
    async with httpx.AsyncClient(headers=headers or {}, timeout=30) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                outputs = []
                for tool, args in calls:
                    result = await session.call_tool(tool, args)
                    outputs.append("\n".join(c.text for c in result.content if hasattr(c, "text")))
                return outputs


def _port_for(lab: str, variant: str) -> int:
    port = PORTS[(lab, variant)]
    if not _port_open(port):
        message = f"lab {lab} {variant} 沒在 {HOST}:{port} 上跑（先 ./labctl.sh up {lab}）"
        # 完整跑（run_all.sh）時 server 沒起來就是失敗，不能靜靜 skip 掉
        if os.environ.get("LAB_STRICT") == "1":
            pytest.fail(message)
        pytest.skip(message)
    return port


@pytest.fixture
def call_tool():
    """call_tool(lab, variant, tool, **args) -> 工具回傳的文字（每次一個新 MCP session）。"""

    def _invoke(lab: str, variant: str, tool: str, **args) -> str:
        return asyncio.run(_session_calls(_port_for(lab, variant), [(tool, args)], None))[0]

    return _invoke


@pytest.fixture
def call_tools():
    """call_tools(lab, variant, [(tool, args), ...], headers=None) -> 每步輸出。

    所有呼叫走「同一個 MCP session」，用來測 session 內的狀態（降權、taint）。
    """

    def _invoke(lab: str, variant: str, calls: list[tuple[str, dict]], headers: dict | None = None) -> list[str]:
        return asyncio.run(_session_calls(_port_for(lab, variant), calls, headers))

    return _invoke
