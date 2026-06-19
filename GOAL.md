# GOAL.md

## Objective

Build a self-contained, local-first app named Skratched: a clean scratchpad, cut-and-paste repository, workspace discovery surface, and experiential memory system that helps a user capture, file, rediscover, connect, and safely reuse past snippets, screenshots, prompts, SQL, API keys, notes, and work artifacts.

The app should feel smart and anticipatory without making the workspace visually busy. The first screen is the usable memory surface: an always-open scratchpad, quick category picks, recent context, fast retrieval, and AI-assisted filing that keeps the user in control.

## Product Requirements

- Provide an always-open scratchpad for rapid paste, typing, drag/drop, and screenshot capture.
- Provide a Workspace Scout mode that scans user-approved local roots for recently changed or stale candidate files such as secrets, configs, code, screenshots, docs, and exact filenames, then presents a metadata-only preview before any content is imported.
- Support category buttons and user-defined shelves such as `prompts`, `SQL queries`, `API-Keys`, `screenshots-work`, `screenshots-products`, `code`, `commands`, `research`, and `follow-up`.
- Auto-file captures with undo, plus optional suggest-only and manual filing modes.
- Keep the display clean and open: retrieval and filing helpers should appear as quick picks, inline suggestions, shelves, and context drawers instead of clutter.
- Make retrieval feel like memory, not database search. Example: "find my last OpenRouter API keys added in the last 3 weeks, and provide context of associated entries."
- Preserve context around each capture: source, timestamp, neighboring entries, project, inferred topic, sensitivity class, related items, duplicate status, and why it was filed that way.
- Detect duplicates, near-duplicates, recurring families, revisions, and related artifacts.
- Support item versioning, deprecation, and replacement tracking so old snippets can point to safer or newer successors without losing history.
- Protect sensitive items. API keys and secrets must be redacted by default, excluded from logs, and revealed only after a local unlock action.
- Provide safe import/export through JSONL or bundle packs with metadata, hashes, and redacted previews.
- Support semantic retrieval, but do not depend on a vector database.

## Memory Architecture Direction

Use a metadata-first architecture inspired by prior CAM work, but keep Skratched standalone. CAM mining and CAM-derived methods may inform implementation; CAM must not be a runtime dependency for the finished app.

Core entities:

- `items`: captured text, images, files, snippets, commands, prompts, keys, queries, and notes.
- `receipts`: capture source, timestamp, content hash, file path or app origin when available, and provenance.
- `facets`: explicit and inferred metadata such as category, project, language, vendor, time window, sensitivity, and shorthand labels.
- `families`: duplicate groups, revision chains, recurring patterns, and related collections.
- `links`: typed cross-index edges such as "mentions", "derived_from", "same_key_family", "used_with", "screenshot_of", "query_for", and "follow_up_to".
- `events`: append-only capture, edit, reveal, export, search, and filing history.
- `summaries`: tiered memory summaries for recent, project, category, and long-horizon recall.
- `safe_exports`: redacted bundles and metadata-only diffs for backup, restore, and future migration.
- `workspace_scans`: scan runs, configured roots, file-type presets, time windows, index freshness, and aggregate scan metrics.
- `workspace_candidates`: metadata-only discovered file candidates with path provenance, mtime, size, type label, stat fingerprint, duplicate/capture status, and approval state.

Persistence and integrity:

- Prefer a local ACID store for queryable metadata plus filesystem/blob storage for larger artifacts such as screenshots and attachments.
- Store deterministic content digests for append-only event integrity, duplicate detection, and import/export verification.
- Use atomic writes and strict local file permissions for config, export, and sensitive metadata files.
- Treat import/export through a storage-manager boundary so backup formats can evolve without breaking older data.
- Treat Workspace Scout discovery as metadata-first indexing. The scout index may cache path, mtime, size, type label, scan root, and stat fingerprint, but must not store file bodies or secret values until the user explicitly approves a capture/import action.
- Support bounded scan roots, depth limits, type presets, exact filename filters, recent/stale time windows, cache refresh controls, and stale-index diagnostics.

Search and recall strategy:

- First layer: exact search, filters, time windows, category shelves, shorthand labels, and structured metadata.
- Second layer: full-text search with weighted fields and recency/context boosts.
- Third layer: graph/cross-index traversal for associated entries and contextual recall.
- Fourth layer: lightweight lexical similarity such as TF-IDF for near matches and duplicate detection.
- Optional layer: small local embeddings or model-assisted semantic scoring when available, always secondary to metadata, receipts, and explainable matches.
- Ranking may use reciprocal rank fusion across exact, FTS, graph, recency, duplicate-family, and optional semantic signals.
- Auto-tagging should start with deterministic, pattern-based rules before any AI call. Examples: API-key/vendor detection, SQL object extraction, code language, command shape, screenshot source, and filename/path hints.
- SQL and code snippets should get specialized extraction when possible, including SQL entity detection, SQL splitting/title generation, normalization, language detection, and complexity scoring.
- Large items should use bounded context assembly, skeleton extraction, and tiered summaries instead of loading entire files or histories into every operation.
- Workspace Scout candidates should be searchable by path, filename, type, root, project, recency, stale status, and prior capture status. Candidate search should explain index age and whether the result came from a fresh scan or cached metadata.
- Approved Workspace Scout imports should become normal Skratched items with receipts, facets, duplicate-family checks, redaction, lifecycle events, and links back to the candidate and scan run that discovered them.

Safety and control model:

- Represent sensitive operations as propose -> check -> apply flows with reversible user approval cards for high-risk actions.
- Use risk classes for items and actions, with at least safe, caution, sensitive, and blocked states.
- Define explicit data-flow rules for secrets, screenshots, exports, logging, diagnostics, and optional AI analysis.
- AI-assisted analysis must have structured output validation and a clear fallback path when the model is unavailable or returns invalid output.
- Workspace Scout must be preview-first and approval-gated. Scanning may collect safe file metadata, but reading file content, importing broad directories, or revealing suspected secrets requires explicit local user action.
- Secret-like candidates such as `.env`, `.key`, `.pem`, `.p12`, `.pfx`, copied credentials, and config files with likely secret material default to metadata-only candidate records unless the user explicitly unlocks or approves redacted capture.

## UX Requirements

- First screen must be the real tool, not a marketing page.
- Capture should be possible in one action.
- Filing should feel fast: category buttons, keyboard-friendly quick picks, inline chips, and reversible AI suggestions.
- Category and tag creation must be race-safe and forgiving: optimistic insert, retry on conflict, then reuse the existing category/tag.
- Search should support plain language, shorthand, filters, and quick refinements.
- Results should show context, not just snippets: why the item matched, adjacent captures, linked entries, sensitivity state, and safe actions.
- The app should think ahead with "likely next" suggestions such as related prompts, last-used API vendor, recent project shelf, duplicate warning, or associated screenshot.
- Workspace Scout should appear as a compact Discover/Scout drawer or panel, not a separate busy app. It should show changed/stale project groups, candidate counts, index age, safe type filters, and one-action approvals for selected captures.
- Scout previews should make the useful next step obvious: capture selected files, ignore, mark stale, refresh scan, open related memory, or link the candidate to an existing item.
- Failed AI analysis or import should produce a useful diagnostic view with connection/storage status and safe retry options.
- Do not expose secret values in previews, logs, exports, screenshots, or test fixtures.

## Reliability Requirements

- Use idempotent database operations for capture, category/tag creation, imports, and duplicate-family updates.
- Validate all API, import, and file boundaries with structured schemas.
- Provide health checks for local storage, index freshness, search availability, and optional AI provider availability.
- Degrade gracefully when optional services are unavailable: capture and deterministic search must continue.
- Keep structured logs with context and timing, but redact sensitive data before it reaches logs or diagnostics.
- Maintain explicit configuration precedence and fallback rules.
- Workspace Scout scans must be bounded by configured roots, depth, file count, size limits, skip directories, and symlink/path traversal guards.
- Workspace Scout cache hits must report their freshness and limitations, including whether newly created files require a refresh/full scan to appear.

## Constraints

- Local-first by default.
- No external cloud service required for core capture, filing, search, duplicate matching, or recall.
- No vector database dependency.
- No CAM runtime dependency.
- No production deployment without explicit user approval.
- No destructive filesystem, database, or secret-handling action without explicit approval.
- No broad workspace import, recursive file-body ingestion, or secret-file content read without explicit approval after a metadata-only preview.
- If a safe assumption is needed later, document it in `PROGRESS.md` and continue.
- Follow the local standing rules from the user-provided `AGENTS.md` instructions.

## CAM Mining Status

On 2026-06-17, the changed-only CAM scan for `/Volumes/WS4TB/repo421sn` found 298 discovered repositories and 156 eligible repositories. The actual mining run scanned 10 selected changed/new repositories, skipped 136 unchanged repositories, saved 113 findings, generated 36 tasks, processed 602,139 tokens, and completed in 858.9 seconds.

Mined repositories:

- `clinical-llm-benchmarks`: 7 findings.
- `macUSB`: skipped, no recognizable source files.
- `mcp-agentify`: 10 findings.
- `mcp-cortex`: 11 findings.
- `oracle`: 10 findings.
- `podgobbler`: 19 findings.
- `snipped`: 23 findings.
- `snipperdoodle`: 15 findings.
- `spawn`: 15 findings.
- `stigmergic-swarm-engine`: 3 findings.

Some generated CAM tasks failed with `FOREIGN KEY constraint failed`, but the mining command itself exited successfully and saved findings. Treat task-generation failures as CAM task-store hygiene, not as a blocker for Skratched.

On 2026-06-17, a second explicit changed-only CAM mine was run against these repositories under `/Volumes/WS4TB/WS4TBr`: `AdmSVE`, `EMEX`, `turboragger`, `finESS`, `gemoptiq`, `sentinel_arbiter`, `OptiqMTPMLX`, `loclM3`, and `RedaktSafe`. The scan-only preview confirmed exactly one eligible repository for each path. The actual mine saved 134 findings, generated 109 tasks, processed 676,871 tokens, and completed the requested repo list.

Second-batch mined repositories:

- `AdmSVE`: 10 findings, 10 tasks.
- `EMEX`: 15 findings, 15 tasks.
- `turboragger`: 15 findings, 15 tasks.
- `finESS`: 22 findings, 12 tasks.
- `gemoptiq`: 15 findings, 15 tasks.
- `sentinel_arbiter`: 11 findings, 11 tasks.
- `OptiqMTPMLX`: 12 findings, 12 tasks.
- `loclM3`: 22 findings, 8 tasks.
- `RedaktSafe`: 12 findings, 11 tasks.

The first wrapper loop stopped after `AdmSVE` because `status` is a read-only zsh variable; `AdmSVE` had already completed successfully. The remaining eight repositories were mined in a corrected loop. Some generated CAM tasks again failed with `FOREIGN KEY constraint failed`, but the corresponding findings were saved.

On 2026-06-18, after switching the active CAM runtime to `z-ai/glm-5.2` primary and `moonshotai/kimi-k2.7-code` secondary/fallback, a focused mine was run for the newly added `/Volumes/WS4TB/repo421sn` repositories `storm`, `codexpro`, and `privacy-filter.cpp`. The run used `--target /Volumes/WS4TB/skratched`, `--force-rescan`, `--no-tasks`, `--depth 1`, `--max-repos 1`, and `--max-minutes 45` per repo. Tasks were intentionally disabled to avoid task-store noise and keep the pass focused on reusable findings.

Third-batch mined repositories:

- `storm`: 14 findings, 62,828 tokens, 129.0 seconds.
- `codexpro`: 11 findings, 58,730 tokens, 115.3 seconds.
- `privacy-filter.cpp`: 17 findings, 140,902 tokens, 166.5 seconds, polyglot split across `misc` and `python` zones.

The third batch saved 42 total findings, generated 0 tasks by design, and produced logs under `/private/tmp/skratched-cam-newmine-20260618-072015`.

Useful CAM-derived methods to carry forward:

- Metadata-first recall and structured provenance.
- FTS-backed local indexes.
- Reciprocal rank fusion over multiple retrieval methods.
- Graph/community clustering for related items without requiring vectors.
- Stdlib-friendly TF-IDF fallback for lexical similarity.
- Secret redaction, metadata-only diffs, and safe backup/export packs.
- Tiered context loading and structured context assembly.
- Pattern-based auto-tagging without AI calls.
- Multi-dimensional tagging taxonomy for snippet and memory retrieval.
- Dual local persistence with ACID metadata and filesystem artifact storage.
- Deterministic digests for append-only logs and import/export verification.
- Human approval cards, risk classes, and data-flow rules for sensitive actions.
- API-key masking/source detection and backend/local proxy patterns for key safety.
- Configurable dedupe, snippet versioning, deprecation, and replacement tracking.
- SQL normalization, SQL file splitting, and deterministic SQL entity extraction.
- Health checks, graceful degradation, input validation, and structured diagnostics.
- Verification patterns using JSON fixtures, property/noise tests, and environment-gated integration tests.
- Provenance-constrained knowledge with mandatory citation, receipt hashes, hash-chained traces, and audit-state skip-on-no-new-action behavior.
- Fail-closed gates for invalid input, leakage, path traversal, future-data leakage, and uncertain high-risk actions.
- Encrypted local snippet storage using password-derived keys and authenticated integrity checks.
- Context canary tests, fake model adapters, and schema-versioned synthetic fixtures for optional AI behavior.
- Deterministic policy/effect vocabulary, command-effect inference, and capability contracts for explainable action safety.
- Workspace-relative safe path resolution with symlink traversal checks.
- Real filesystem observation with stat-based fingerprints for capture freshness and local artifact drift.
- Approval queues with explicit pending decisions, keyboard-first actions, and idempotent approval gates.
- Domain-adaptive prompt selection, model-aware instruction injection, per-model timeout/retry/cost ceilings, and structured OpenRouter client accounting.
- Session-scoped API-key or path overrides with TTL and without disk persistence.
- Separate lightweight embedding models from chat models when optional semantic scoring is enabled.
- Protocol-safe stdout/stderr hygiene, best-effort JSON parse/retry, and tolerant multi-format tool-call parsing.
- Redacted trace galleries, structured readiness proof matrices, summary-first result presentation, and learning-corpus coverage summaries.
- Role-based multi-model pipeline configuration with per-stage model assignment and cost/timing attribution.
- Dynamic hierarchical knowledge insertion, background research warm starts, citation extraction/index remapping, and hash-based information deduplication.
- Granular callback lifecycle hooks, pipeline timing wrappers, and context-manager logging for explainable capture/recall flows.
- Timing-safe token authentication, layered path guards with symlink escape prevention, shell allowlists, sanitized command environments, and placeholder-aware secret redaction.
- Deterministic AI context bundle export, hierarchical `AGENTS.md`/instruction discovery, tool-mode gating, layered config sources, and CSP-safe self-contained widgets.
- Sliding-window/halo processing for long artifacts, constrained sequence decoding, parity gates, differential testing, dry-run artifact publishing, generated-file regeneration checks, and rich benchmark/status visualizations.

## Proof Of Done

The first complete development milestone should include:

- A runnable local app with the primary scratchpad, category shelves, capture flow, search flow, and item detail/context view.
- A durable local data store schema for items, receipts, facets, families, links, events, summaries, and safe exports.
- Capture/search/index lifecycle events with redacted timing diagnostics.
- Stable IDs for items, references, citations/URLs, duplicate families, and import/export bundle entries.
- Long-artifact chunking with overlap windows, boundary metadata, and tests.
- Path normalization and symlink escape tests for any file import or drag/drop path.
- Secret-redaction fixtures covering fake OpenRouter keys, placeholders, `.env`-style lines, SQL credentials, and copied shell commands.
- Dry-run export previews with hashes and redacted previews.
- Tests for capture, filing, search ranking, duplicate matching, version/replacement tracking, secret redaction, export redaction, SQL/code extraction, import/export integrity, and associated-entry recall.
- Differential/property tests for dedupe, redaction, ranking, import/export integrity, long-artifact chunking, and context assembly.
- Fixture-driven tests for representative prompts, SQL queries, API keys, screenshots, duplicate snippets, and mixed project timelines.
- A documented verification command set.
- Local health checks for storage, indexes, redaction, and optional AI analysis.
- Workspace Scout proof covering configured scan roots, metadata-only candidate previews, recent/stale filters, exact filename/type filters, depth limits, cache freshness reporting, duplicate candidate suppression, approval-gated capture, and symlink/path traversal rejection.
- Workspace Scout UI proof showing a compact Discover/Scout drawer with candidate groups, index age, safe approval actions, and no secret leakage in previews or logs.
- A short `PROGRESS.md` update with implementation status, assumptions, and known gaps.
- A demo flow that proves the example query: "find my last OpenRouter API keys added in the last 3 weeks, and provide context of associated entries."

## Stop Conditions

Stop and ask before:

- handling real credentials beyond redacted/local test data,
- connecting cloud providers,
- deploying,
- deleting or overwriting user data,
- importing large private corpora into a new store,
- making a product decision that materially reduces the agreed "WOW / SMART / user-friendly / thinks ahead / experiential memory" requirement.
