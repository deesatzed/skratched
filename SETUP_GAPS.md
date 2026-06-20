# Setup Gap Log

Gaps found while verifying that `git clone` → documented README steps → running app works from a completely clean environment (fresh venv, no cached deps, no preinstalled browser).

## Gap Log

### 2026-06-19 - Gap #1

**Problem:** README's "Verify" section instructs running `node scripts/browser_smoke.mjs --base-url http://127.0.0.1:8787` but never states that this script requires a real local Chrome/Chromium binary on disk. The script does not depend on the `playwright` npm/pip package; it drives Chrome directly over the DevTools Protocol via hardcoded binary search paths (including a path specific to the original author's machine, `/Users/.../Library/Caches/ms-playwright/...`). On a clean machine with no Chrome/Chromium installed, the command fails immediately with `Error: No Chromium/Chrome executable found. Set SKRATCHED_CHROME or pass --chrome.` with no prior warning in the docs.

**Fix:** Added a "Prerequisite" callout in README.md directly above the browser-smoke command, listing the exact binary search order (`--chrome` flag, `SKRATCHED_CHROME` env var, then default OS paths), the exact failure message a contributor will see, and a copy-pasteable `--chrome` override example. Also clarified that this step is local-only and intentionally excluded from CI (confirmed against `.github/workflows/ci.yml`, which omits it), so a contributor isn't left wondering whether CI is silently broken.

**Verification:** Confirmed in next clean run — fresh clone into `/tmp/skratched-ghsetup-verify`, fresh venv, `pip install -e .`, full unit test suite (125 tests, OK), `py_compile` checks, `node --check` on both JS files, and `python scripts/demo_flow.py` all pass with zero hidden assumptions. Live server smoke (`skratched-server` + documented `/api/capture`, `/api/capture-file`, `/api/search` calls with fake keys only) confirmed working end-to-end. The browser-smoke gap itself is now pre-disclosed rather than silently failing; re-running it on a machine with Chrome installed (or with `--chrome` pointed at one) is the actual fix path for that one step, which is unchanged in behavior — only the documentation gap is closed.

### 2026-06-20 - Verification Pass: MCP Server Addition

**Context:** Added an MCP (Model Context Protocol) server (`skratched-mcp`, `mcp>=1.28.0` dependency, `skratched/mcp_server.py`) per `docs/plans/2026-06-19-mcp-server.md`. Re-ran the full clean-clone protocol against commit `b94ca35` to confirm the new dependency and entrypoint don't introduce a setup gap.

**Result: no new gap found.** Fresh clone into `/tmp/skratched-mcp-clean-verify`, fresh venv, `pip install -e .` resolved `mcp` and its transitive deps (httpx, pydantic, starlette, etc.) with zero conflicts in the isolated venv. `skratched-server --help`, `python -c "import skratched.mcp_server"`, and `which skratched-mcp` all succeeded. Full unit suite (159 tests), `py_compile` (now including `skratched/mcp_server.py`), both `node --check` syntax checks, and `python scripts/demo_flow.py` all passed unchanged.

**Additional verification beyond the documented Verify block:** ran the actual MCP JSON-RPC wire protocol (`initialize` → `notifications/initialized` → `tools/list` → `tools/call`) against a live `skratched-mcp` subprocess from the clean clone — not just unit tests against the Python functions. Confirmed: all 6 documented tools are discoverable via `tools/list`; `skratched_capture_tool` → `skratched_search_tool` round-trips correctly against a real on-disk store; and critically, `skratched_reveal_tool` called against a real secret-classified item (`sensitivity: "sensitive"`) with no TTY attached to the subprocess returns `{"confirmed": false}` with no `item`/value in the response — the core safety property (no silent secret reveal to an agent) holds over the actual protocol, not just in mocked unit tests.

**Observation, not a gap in this repo:** installing into a *shared, non-fresh* global conda env (`py313`) that also has `semgrep` installed surfaced a pip dependency warning: `semgrep 1.153.0 requires mcp==1.23.3, but you have mcp 1.28.0`. This is expected and harmless for Skratched's own isolated `pip install -e .` (confirmed clean in a fresh venv with nothing else installed) — flagged here only so a future contributor isn't alarmed if they see the same warning when installing into a pre-existing env that also has `semgrep` or another `mcp`-pinning tool.

**Verification:** Confirmed in the clean run described above. No README/docs changes were needed beyond what `docs/plans/2026-06-19-mcp-server.md` Task 7 already added (MCP Server section, Verify block update, CI workflow update).
