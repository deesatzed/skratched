# IMPLEMENTATION_PACKET.md

## Task Being Attempted

Build the first self-contained Skratched vertical slice from `GOAL.md`.

## Actual User Goal

Create a local-first scratchpad and experiential memory app that can capture snippets, auto-classify/redact them, store durable metadata locally, search/retrieve associated context, and prove the OpenRouter API key recall workflow without CAM as a runtime dependency.

## Files Expected To Change

| File | Expected Change | Risk |
|---|---|---|
| `skratched/__init__.py` | Package marker and version | Low |
| `skratched/analyze.py` | Deterministic classification, redaction, tags, summaries, chunking | Medium |
| `skratched/storage.py` | SQLite schema and persistence/search APIs | Medium |
| `skratched/export.py` | Redacted dry-run export bundles | Low |
| `server.py` | Stdlib HTTP server for local app/API/static assets | Medium |
| `static/index.html` | First-screen app shell | Low |
| `static/styles.css` | Clean open UI styling | Low |
| `static/app.js` | Browser capture/search interactions | Medium |
| `tests/*.py` | Tests for the first vertical slice | Low |
| `PROGRESS.md` | Status update after implementation | Low |

## Existing Patterns To Follow

- Use `GOAL.md` as the product and proof-of-done source of truth.
- Keep core behavior local-first and self-contained.
- Prefer deterministic metadata, FTS, recency, duplicate families, and explicit context links before optional semantic scoring.
- Keep secrets redacted in previews, logs, exports, and tests.
- Use CAM-derived acceptance criteria now embedded in `GOAL.md`: lifecycle events, stable IDs, long-artifact chunking, symlink/path safety, dry-run exports, and differential/property-style tests.

## Assumptions

- Python stdlib + SQLite is acceptable as the first self-contained local app stack.
- Browser UI can be served by `server.py`; no npm, bundler, external service, or vector DB is required.
- Screenshot capture can start as file/drag-drop metadata support in this slice; OS-level screenshot capture is outside this pass.
- Test fixtures must use fake keys only.

## Non-Goals For This Pass

- No CAM runtime integration.
- No cloud provider connection.
- No real secret import.
- No production deployment.
- No external package installation.
- No full optional embedding model implementation.

## Step-by-Step Plan

1. Write failing tests for deterministic analysis, secret redaction, duplicate detection, FTS/context recall, dry-run export, chunking, and path safety.
2. Implement the minimal Python package to make those tests pass.
3. Add the stdlib HTTP API and static browser UI.
4. Run tests and a server smoke check.
5. Update `PROGRESS.md` with verified status and remaining gaps.

## Acceptance Criteria

- `python -m unittest discover -s tests` passes.
- App starts with `python server.py --host 127.0.0.1 --port 8787`.
- API supports capture, listing categories, search, health, and dry-run export.
- Captured fake OpenRouter keys are redacted by default and categorized as `API-Keys`.
- Search can answer the demo workflow by returning recent fake OpenRouter API key items plus associated context.
- SQLite schema includes items, receipts, facets, families, links, events, summaries, and safe_exports tables.
- Exports include hashes and redacted previews.
- Tests cover redaction, duplicate families, associated-entry recall, long-artifact chunking, symlink/path safety, and export integrity.

## Verification Plan

- Run `python -m unittest discover -s tests`.
- Run a short API smoke test against `server.py` using `curl` or a Python stdlib client.
- Inspect no real secret values are present in test fixtures or logs.

## Rollback Plan

Because `/Volumes/WS4TB/skratched` is not a git repository, rollback is manual: remove the newly added `skratched/`, `static/`, `tests/`, `server.py`, and `IMPLEMENTATION_PACKET.md` files if this pass is rejected.

## Risks

| Risk | Mitigation |
|---|---|
| First slice becomes too broad | Keep implementation to deterministic local capture/search/export. |
| Secret handling leaks values | Redaction tests use fake keys and assert raw secrets are absent from previews/exports. |
| UI polish lags backend | Build a simple but usable first screen with clean layout and no marketing page. |
| SQLite schema overfits | Use simple tables and JSON metadata fields where flexibility is useful. |

## Proceed / Block Decision

Proceed. No blocker: all required inputs are in the workspace, and the first slice can be implemented locally without credentials or external services.
