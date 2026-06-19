# Setup Gap Log

Gaps found while verifying that `git clone` → documented README steps → running app works from a completely clean environment (fresh venv, no cached deps, no preinstalled browser).

## Gap Log

### 2026-06-19 - Gap #1

**Problem:** README's "Verify" section instructs running `node scripts/browser_smoke.mjs --base-url http://127.0.0.1:8787` but never states that this script requires a real local Chrome/Chromium binary on disk. The script does not depend on the `playwright` npm/pip package; it drives Chrome directly over the DevTools Protocol via hardcoded binary search paths (including a path specific to the original author's machine, `/Users/.../Library/Caches/ms-playwright/...`). On a clean machine with no Chrome/Chromium installed, the command fails immediately with `Error: No Chromium/Chrome executable found. Set SKRATCHED_CHROME or pass --chrome.` with no prior warning in the docs.

**Fix:** Added a "Prerequisite" callout in README.md directly above the browser-smoke command, listing the exact binary search order (`--chrome` flag, `SKRATCHED_CHROME` env var, then default OS paths), the exact failure message a contributor will see, and a copy-pasteable `--chrome` override example. Also clarified that this step is local-only and intentionally excluded from CI (confirmed against `.github/workflows/ci.yml`, which omits it), so a contributor isn't left wondering whether CI is silently broken.

**Verification:** Confirmed in next clean run — fresh clone into `/tmp/skratched-ghsetup-verify`, fresh venv, `pip install -e .`, full unit test suite (125 tests, OK), `py_compile` checks, `node --check` on both JS files, and `python scripts/demo_flow.py` all pass with zero hidden assumptions. Live server smoke (`skratched-server` + documented `/api/capture`, `/api/capture-file`, `/api/search` calls with fake keys only) confirmed working end-to-end. The browser-smoke gap itself is now pre-disclosed rather than silently failing; re-running it on a machine with Chrome installed (or with `--chrome` pointed at one) is the actual fix path for that one step, which is unchanged in behavior — only the documentation gap is closed.
