# MCP Server for Skratched

**For Codex:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let Claude Code, Codex, or any MCP-capable agent search, capture, and inspect Skratched memory mid-session, and trigger Workspace Scout scans, without breaking the existing redaction/approval safety model. No new persistence, no new redaction rules — this is a thin MCP transport in front of the existing `dispatch_api` REST surface in `server.py`.

**Decisions (user-approved 2026-06-19):**
- Reveal of a real secret value is **never** returned to an agent silently. Each reveal call blocks on a synchronous stdin TTY confirmation prompt on the MCP server process before the unredacted value is returned. If the human declines, the prompt has no attached TTY, or it times out, the call returns redacted output — never an error that leaks shape/length hints beyond what `/api/reveal` already exposes today.
- MCP SDK dependency: `mcp>=1.28.0` (official Model Context Protocol Python SDK, current PyPI latest as of 2026-06-19, requires Python >=3.10 — compatible with this project's `>=3.13` floor).
- Transport: stdio, direct `SkratchedStore` import (no HTTP hop). Confirmed over the HTTP-bridge alternative.
- `skratched_workspace_scan` roots are restricted to a small explicit allowlist set once via config/env (e.g. `SKRATCHED_MCP_ALLOWED_ROOTS`), not a per-call live approval UI. No new approval surface to build.
- This is a plan/scope document. Implementation proceeds task-by-task below; each task's own tests must pass before moving to the next (per workspace validation-gate rule).

**Architecture:**
- New top-level module `skratched/mcp_server.py` using the stdlib plus the `mcp` package (`mcp>=1.28.0`, added to `pyproject.toml` dependencies — this is the first non-empty entry in that list, a deliberate change from the current zero-dependency baseline).
- The MCP server is a process that talks to the **same `SkratchedStore`** instance model used by `server.py`, not a second copy of business logic. It runs as a local subprocess Claude Code/Codex launches per the client's MCP config (stdio transport), importing `skratched.storage.SkratchedStore` directly and opening the same `data/skratched.db`.
- Reuse existing validation/redaction code paths (`skratched.analyze.redact_text`, `store.health_report()`, `store.search()`, etc.) — the MCP tool handlers should look like thin wrappers around the same calls `dispatch_api` already makes, not new logic.

**Tool surface (6 tools, not a 1:1 mirror of all ~30 REST routes):**

1. `skratched_search(query: str, limit?: int)` → redacted results from `store.search()`. Primary "check before asking the user" tool. Tool description should explicitly instruct agents to call this before assuming something hasn't been solved before.
2. `skratched_capture(text: str, project?: str, category?: str, source?: str)` → `store.capture()`. Lets an agent persist a decision, workaround, or root cause mid-task.
3. `skratched_context(item_id: str)` → `store.context_graph()`. Associated links/duplicates/neighbors for a search hit, so the agent gets the surrounding memory, not just one row.
4. `skratched_health()` → `store.health_report()`. Cheap pre-flight so an agent can detect "Skratched isn't running/reachable" and degrade gracefully instead of failing on the first real call.
5. `skratched_workspace_scan(root: str, preset?: str, max_age_days?: int)` → `store.scan_workspace_candidates()` (metadata-only preview path only; the existing `/api/workspace/capture` approval-gated import stays out of MCP v1 — scanning is safe to expose, importing file content is not, until this plan's reveal-equivalent question is settled for file imports too). `root` must resolve (after symlink-safe normalization, reusing the existing path-safety helper) to a path under one of the entries in `SKRATCHED_MCP_ALLOWED_ROOTS`; otherwise the call fails closed with a clear error naming the allowlist env var, not a silent empty result.
6. `skratched_reveal(item_id: str, reason: str)` → blocks on a stdin TTY confirmation prompt (`input()`-style `y/N`) on the MCP server process. If the process has no attached TTY (`sys.stdin.isatty()` is false) or the human answers anything but explicit confirmation, returns `{"confirmed": false, "reason": "..."}` with redacted output — never raises in a way that implies the value almost leaked. On confirmation, returns the real value once and logs an audit event via the existing `events`/hash-chain mechanism in `storage.py` (no parallel audit log).

**Explicitly out of scope for v1:** export/import, filing/shelves mutation, action propose/check/apply, screenshot watcher control. These either mutate significant state or have no clear "agent reaches for this mid-task" justification yet. Add later only on demonstrated need.

---

### Task 1: Dependency Declaration

**Files:** `pyproject.toml`

**Steps:**
1. Add `mcp>=1.28.0` to `[project].dependencies` (currently empty list — this is the first real dependency added to this project).
2. Confirm `pip install -e .` still succeeds cleanly and pulls `mcp` and its transitive deps.

### Task 2: Reveal Confirmation Mechanism

**Files:** `skratched/mcp_server.py` (new), possibly `skratched/storage.py` (read-only addition, no schema change)

**Steps:**
1. Write failing tests describing the exact confirmation contract: what `skratched_reveal` returns when (a) confirmed via stdin `y`, (b) declined via stdin `n`/anything else, (c) no TTY attached (`sys.stdin.isatty()` false), (d) timeout if one is added. Tests should inject/mock the confirmation hook rather than requiring a real attached terminal in CI.
2. Implement the stdin-prompt confirmation hook as a small, separately-testable function (e.g. `confirm_reveal(item_id: str, reason: str) -> bool`) so the prompt logic isn't tangled with the MCP tool handler.
3. Implement the tool handler using that hook.

### Task 3: Core Read Tools

**Files:** `skratched/mcp_server.py`, `tests/test_mcp_server.py`

**Steps:**
1. Write failing tests for `skratched_search`, `skratched_context`, `skratched_health` against a temporary `SkratchedStore`, asserting redacted-by-default output matches what `/api/search` etc. already return (parity, not new behavior).
2. Implement the three tools as thin wrappers.
3. Run focused tests, then full suite.

### Task 4: Capture Tool

**Files:** `skratched/mcp_server.py`, `tests/test_mcp_server.py`

**Steps:**
1. Write failing tests for `skratched_capture` covering text/project/category/source plumbing and redaction-on-write parity with `/api/capture`.
2. Implement, test, verify no drift from REST behavior.

### Task 5: Workspace Scan Tool

**Files:** `skratched/mcp_server.py`, `skratched/config.py` (add `SKRATCHED_MCP_ALLOWED_ROOTS` parsing, following the existing env-var precedence pattern), `tests/test_mcp_server.py`

**Steps:**
1. Write failing tests for `skratched_workspace_scan` confirming: (a) only metadata-only previews are returned, no file content and no capture side effect; (b) a root outside `SKRATCHED_MCP_ALLOWED_ROOTS` fails closed with a clear error naming the env var; (c) symlink-escape attempts are rejected via the same path-safety helper `/api/workspace/scan-preview` already uses.
2. Implement, test.

### Task 6: Reveal Tool

**Files:** `skratched/mcp_server.py`, `tests/test_mcp_server.py`

**Steps:**
1. Implement against the stdin-prompt mechanism built in Task 2.
2. Tests must prove: declined/no-TTY paths never return the real value; confirmed path returns the real value once and logs an audit event (reuse existing `events`/hash-chain pattern from `storage.py`, do not invent a parallel audit log).
3. Tests must prove the real value, once revealed to the MCP tool response, is never additionally logged in redacted form anywhere (no double-write of the secret to disk in plaintext beyond what already exists in the original captured item).

### Task 7: Packaging and Docs

**Files:** `pyproject.toml`, `README.md`, `skratched/cli.py` or new `skratched/mcp_cli.py`

**Steps:**
1. Add `skratched-mcp` console script entrypoint.
2. Document in README: how to register the server with Claude Code (`.mcp.json` / `claude mcp add` pattern) and Codex's MCP config, the 6 tools and what each does, the `SKRATCHED_MCP_ALLOWED_ROOTS` setup step required before Workspace Scout works over MCP, and the reveal-confirmation UX in plain language so a user isn't surprised by a terminal prompt mid-agent-session.
3. Add a CI compile/syntax check for the new module, matching the existing `py_compile` step.

### Task 8: Clean-Clone Verification

**Steps:**
1. Re-run the same hermetic clean-clone verification process used for the REST API (fresh clone, fresh venv) against the new MCP server and its README instructions.
2. Log any gaps in `SETUP_GAPS.md`, same protocol as before.

---

All three open design questions from the initial scope are resolved (SDK version, reveal channel, Scout root scope — see Decisions above). Implementation can proceed task-by-task with no further blocking decisions identified at this time. If anything surfaces mid-implementation that isn't covered here (e.g. a concrete `mcp` SDK API shape that conflicts with an assumption above), stop and flag it rather than guessing past it.
