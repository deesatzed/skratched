# CAM KB Reassessment: Skratched

Date: 2026-06-18

## Purpose

Reassess whether the newest CAM knowledge-base additions from `storm`, `codexpro`, and `privacy-filter.cpp` are represented in the Skratched plan, and promote valuable items from broad carry-forward notes into concrete build requirements.

Evidence sources:

- Live CAM DB: `/Volumes/WS4TB/WS4TBr/CAM_Codx/CAM_CAM/data/claw.db`
- TypeScript brain DB: `/Volumes/WS4TB/WS4TBr/CAM_Codx/CAM_CAM/instances/typescript/claw.db`
- Misc brain DB: `/Volumes/WS4TB/WS4TBr/CAM_Codx/CAM_CAM/instances/misc/claw.db`
- Run logs: `/private/tmp/skratched-cam-newmine-20260618-072015`
- Product source of truth: `GOAL.md`

## Reassessment Verdict

The Skratched plan already includes the major useful themes: metadata-first recall, provenance, duplicate detection, graph links, redaction, safe import/export, optional semantic scoring, structured diagnostics, and no CAM runtime dependency.

The plan should still be tightened before implementation by converting the newest mined patterns into explicit acceptance criteria. These additions are not scope expansion; they make the existing goals testable and harder to accidentally omit.

## High-Value Findings And Coverage

| CAM source | Finding cluster | Current coverage | Plan action |
|---|---|---|---|
| `storm` | Dynamic hierarchical knowledge insertion, citation/index remapping, background warm starts | Partly covered by summaries, links, facets, and context assembly | Add a first-class `memory trail`/`context chain` view model and stable reference IDs for extracted URLs/citations. |
| `storm` | Lifecycle callbacks, timing/cost attribution, pipeline-stage logging | Partly covered by events and structured diagnostics | Add capture/search/index lifecycle events with timings, redaction-safe payloads, and health panels. |
| `storm` | Deduplication through stable hashes and citation UUIDs | Covered broadly | Keep as MVP requirement for content hashes, duplicate families, and stable item/reference IDs. |
| `codexpro` | Layered path guard, symlink escape prevention, shell allowlist, sanitized command environment | Mentioned as safe path resolution and data-flow rules | Promote to explicit file/import boundary tests before drag/drop or folder import. |
| `codexpro` | Structured secret redaction with placeholder awareness | Covered broadly | Add fixture tests for real-looking fake API keys, placeholders, env-style secrets, and redacted exports. |
| `codexpro` | Deterministic context bundle export with byte budgeting | Partly covered by export and bounded context assembly | Add redacted `context bundle` export as a post-MVP or late-MVP feature, useful for AI handoff/prompt reuse. |
| `codexpro` | Hierarchical instruction discovery and tool-mode gating | Partly covered by category/shelf behavior and optional AI control | Use the pattern for project/workspace context discovery, but do not add MCP/tool server scope to MVP. |
| `privacy-filter.cpp` | Overlapping halo windows and long-document boundary semantics | Partly covered by tiered summaries and bounded context loading | Add deterministic long-artifact chunking with overlap metadata and boundary tests. |
| `privacy-filter.cpp` | Differential testing, fuzz/property tests, parity gates | Covered broadly in proof-of-done tests | Promote to concrete test families for redaction, dedupe, import/export, ranking, and long-artifact chunking. |
| `privacy-filter.cpp` | Dry-run artifact publishing and generated-file regen checks | Partly covered by safe exports | Add export dry-run/preview mode and manifest/hash verification. |
| `privacy-filter.cpp` | BIOES/Viterbi sequence decoding and SIMD/C API patterns | Low direct value for MVP | Defer unless local entity extraction becomes model-like enough to need constrained decoding. |

## Required Plan Tightening

Before implementation starts, update the build checklist so the first vertical slice includes:

1. Capture/search/index lifecycle events with redacted timing diagnostics.
2. Stable IDs for items, references, citations/URLs, duplicate families, and import/export bundle entries.
3. Long-artifact chunking with overlap windows, boundary metadata, and tests.
4. Path normalization and symlink escape tests for any file import or drag/drop path.
5. Secret-redaction fixtures covering fake OpenRouter keys, placeholders, `.env`-style lines, SQL credentials, and copied shell commands.
6. Dry-run export previews with hashes and redacted previews.
7. Differential/property tests for dedupe, redaction, ranking, import/export integrity, and context assembly.

## Deferred Items

These mined ideas are valuable but should not enter the first build slice unless they become necessary:

- MCP server transport and session management.
- Runtime SIMD dispatch and C ABI design.
- Full constrained sequence decoder for entity extraction.
- Multi-agent moderator turn policy.
- Self-contained model converter and nightly model-asset parity.

## Implementation Rule

Treat this reassessment as a requirements refinement, not a dependency decision. Skratched remains self-contained and must not depend on CAM at runtime.
