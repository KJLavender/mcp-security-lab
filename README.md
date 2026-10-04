# MCP Security Lab — Breach-to-Fix practice log

**English** | [繁體中文](README.zh-TW.md)

Working through the 9 MCP vulnerability scenarios in [PawelKozy/mcp-breach-to-fix-labs](https://github.com/PawelKozy/mcp-breach-to-fix-labs):
reproduce each attack, write my own fix, and verify it with protocol-level pytest regression tests (sending MCP `tools/call` directly, no AI in the loop).

> This repo does **not** include the lab source code (upstream has no LICENSE). It contains only my fixes (`mine/`), the tests (`tests/`), notes and runner scripts.
> When it needs seed data, `mine/` runs `import server as upstream` inside the container to reuse the official data instead of copying the code.

## Layout

| Path | Contents |
|---|---|
| `mine/labNN/server.py` | My fixed MCP server |
| `mine/lab04/readonly_role.sql` | The main control for Lab 04: a read-only DB role |
| `tests/test_labNN_*.py` | Regression tests per lab (vulnerable must be breached, fixed must block, normal functionality must keep working) |
| `labctl.sh` | Starts/stops all labs with docker in WSL (vulnerable / official secure / mine, bound to 127.0.0.1 only) |
| `inspector_repro.sh` | Reproduces each lab's core attack with the MCP Inspector CLI; raw responses go to `evidence/inspector/` |
| `runtests.sh` / `run_all.sh` | Run pytest in a throwaway container / rebuild + test + tear down in one step |
| `NOTES.md` | Per-lab notes (Traditional Chinese): attack surface, root cause, my fix, differences from the official fix, takeaway |

## How to run

```bash
git clone https://github.com/PawelKozy/mcp-breach-to-fix-labs ~/mcp-labs/mcp-breach-to-fix-labs
./run_all.sh -v          # rebuild all containers → pytest → tear down
KEEP_UP=1 ./run_all.sh   # keep the containers running afterwards to poke at them with MCP Inspector
```

Every test runs against three targets:

- `vulnerable`: the attack must succeed (proves the vulnerability exists and the test is valid)
- `secure` (official fix) and `mine` (my fix): the attack must be blocked, and normal functionality must still work
- Tests marked `xfail(strict)` are **gaps that remain in the official secure build**: secure is expected to fail, mine must pass

## Results

On fresh containers: **137 passed, 10 xfailed, 0 failed, 0 skipped**.

The 10 xfails are gaps I found in the official fixes, each captured as a regression test that my fix passes:

- **Lab 05 / 06 / 09**: security state is kept in `threading.local`, but FastMCP 1.x runs sync tools on the event-loop thread, so it's effectively process-global — one session reading untrusted content locks out every session (3 tests)
- **Lab 09**: `grant_admin_permissions()` is a tool the LLM can call, so an injected agent can escalate itself and read the webhook secret
- **Lab 04**: connects as a database superuser, so `SELECT pg_read_file('/etc/passwd')` still reads files on the DB host; the semicolon check also rejects valid queries like `SELECT ';'`
- **Lab 06**: the internal-IP check splits strings on `.`, so `0.0.0.0/0` and `::ffff:192.168.1.100` are accepted
- **Lab 07**: stored ticket content is returned to the LLM as raw text, with no data/instruction boundary
- **Lab 08**: re-initializing a repo with the same name `rmtree`s the existing one first

Details are in [NOTES.md](NOTES.md#測試結果).
