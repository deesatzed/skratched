# Release Readiness Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add public reproducibility, CI, package metadata, generated-artifact parity checks, and a v0.1.0 release tag for Skratched.

**Architecture:** Keep the current local-first runtime intact. Add packaging metadata and a thin console wrapper around the existing `server.py` entrypoint, add a GitHub Actions workflow that runs the documented verification commands, and add tests that fail when generated proof commands drift from their documented schema/output contracts.

**Tech Stack:** Python stdlib, unittest, setuptools via `pyproject.toml`, Node for browser-smoke syntax checks, GitHub Actions, git tags.

---

### Task 1: Package Entrypoint

**Files:**
- Create: `pyproject.toml`
- Create: `skratched/cli.py`
- Test: `tests/test_packaging.py`
- Modify: `README.md`

**Steps:**
1. Write failing tests that parse `pyproject.toml` and verify the `skratched-server` console script points to `skratched.cli:main`.
2. Run the focused packaging test and confirm it fails because files/metadata are missing.
3. Add `pyproject.toml` with setuptools metadata, include the `skratched` package, top-level `server.py`, and static assets.
4. Add `skratched/cli.py` as a thin wrapper around `server.main`.
5. Update README run instructions with `python -m pip install -e .` and `skratched-server`.

### Task 2: Generated-Artifact Parity

**Files:**
- Create: `tests/test_generated_artifacts.py`
- Modify: `README.md`

**Steps:**
1. Write failing tests that run `scripts/demo_flow.py` and validate the `skratched.demo_flow.v1` schema plus documented invariants.
2. Add README parity text documenting that generated proof artifacts are guarded by tests.
3. Run the focused test and then the full suite.

### Task 3: CI

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `README.md`

**Steps:**
1. Add a GitHub Actions workflow on push/pull_request for Python 3.13.
2. Run the exact documented commands except the real browser smoke, which remains local because it requires a Chromium binary and host permissions.
3. Include `pip install -e .` and `skratched-server --help` so package metadata is exercised in CI.

### Task 4: Clean-Clone Proof

**Files:**
- Modify: `PROGRESS.md`

**Steps:**
1. Commit and push implementation changes.
2. Clone `https://github.com/deesatzed/skratched.git` into `/tmp` or `/private/tmp`.
3. Run install and README verification commands from the clean clone.
4. Record the proof in `PROGRESS.md`, commit, and push.

### Task 5: Release Tag

**Files:**
- Modify: `PROGRESS.md`

**Steps:**
1. Wait for GitHub Actions to pass on `main`.
2. Create annotated tag `v0.1.0`.
3. Push the tag.
4. Verify the tag exists on the remote.
