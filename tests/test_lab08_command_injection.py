"""Lab 08：CLI wrapper 指令注入（GHSA-3q26-f695-pp76）。"""
import uuid

import pytest

from conftest import FIXED, official_gap

FLAG = "FLAG{git_command_injection_cve}"
SECRET = "/app/secrets/deployment_token.txt"

INJECTIONS = [
    pytest.param(f"x; cat {SECRET}", id="semicolon"),
    pytest.param(f"x && cat {SECRET}", id="and"),
    pytest.param(f"$(cat {SECRET})", id="subshell"),
    pytest.param(f"`cat {SECRET}`", id="backtick"),
    pytest.param(f"x | cat {SECRET}", id="pipe"),
]


@pytest.mark.parametrize("payload", INJECTIONS)
def test_vulnerable_executes_injected_command(call_tool, payload):
    assert FLAG in call_tool("08", "vulnerable", "init_bare_repository", repo_name=payload)


@pytest.mark.parametrize("variant", FIXED)
@pytest.mark.parametrize(
    "payload",
    INJECTIONS + [
        pytest.param("../escape", id="traversal"),
        pytest.param("x\ncat /etc/passwd", id="newline"),
        pytest.param("", id="empty"),
    ],
)
def test_fixed_blocks_injection(call_tool, variant, payload):
    out = call_tool("08", variant, "init_bare_repository", repo_name=payload)
    assert FLAG not in out
    assert "Initialized" not in out


@pytest.mark.parametrize("variant", ["vulnerable", *FIXED])
def test_normal_repo_creation_works(call_tool, variant):
    name = f"repo-{uuid.uuid4().hex[:6]}"
    assert "Initialized empty Git repository" in call_tool("08", variant, "init_bare_repository", repo_name=name)
    assert name in call_tool("08", variant, "list_repositories")


@pytest.mark.parametrize("variant", official_gap("同名再 init 會先 rmtree：被注入的 agent 可藉此刪掉既有 repo"))
def test_reinit_does_not_destroy_existing_repo(call_tool, variant):
    name = f"keep-{uuid.uuid4().hex[:6]}"
    call_tool("08", variant, "init_bare_repository", repo_name=name)
    out = call_tool("08", variant, "init_bare_repository", repo_name=name)
    assert "already exists" in out
