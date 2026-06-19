# Wow Landing Page Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Turn the GitHub README into a visually grounded, benefit-led landing page with competitive positioning and real screenshots.

**Architecture:** Keep the app first screen unchanged as the real scratchpad, and make the public landing surface the README. Add tracked screenshots under `docs/assets/`, generate them from a local synthetic demo database, and add a regression test that ensures the README references the assets and includes the core benefit/competition/features sections.

**Tech Stack:** Markdown README, Python unittest, Node/Chrome DevTools Protocol screenshot generation, existing stdlib server.

---

### Task 1: Landing Page Contract Test

**Files:**
- Create: `tests/test_readme_landing.py`
- Modify: `README.md`

**Steps:**
1. Write a failing test that checks README contains a hero promise, user-benefit section, competitive comparison section, complete feature map section, and references to tracked screenshot files.
2. Run the focused test and verify it fails before README/screenshots are added.

### Task 2: Screenshot Assets

**Files:**
- Create: `docs/assets/skratched-workspace.png`
- Create: `docs/assets/skratched-context-map.png`
- Create: `docs/assets/skratched-redacted-export.png`
- Create: `scripts/generate_readme_screenshots.mjs`

**Steps:**
1. Add a generator that starts the local app on a temporary SQLite store, seeds fake demo captures, drives the UI in headless Chromium, and writes screenshots.
2. Run the generator and confirm PNG files exist with real PNG signatures.

### Task 3: README Rewrite

**Files:**
- Modify: `README.md`

**Steps:**
1. Rewrite the top of README as a landing page: concrete problem, why users want it, screenshots, competitive positioning by category, feature map, and quick start.
2. Keep claims tied to implemented behavior and avoid replacing the app’s first screen with marketing content.

### Task 4: Verification and Publish

**Files:**
- Modify: `PROGRESS.md`

**Steps:**
1. Run focused README landing tests, full suite, compile checks, JS syntax checks, demo proof, and screenshot generator.
2. Update PROGRESS with the landing-page/screenshots proof.
3. Commit and push.
