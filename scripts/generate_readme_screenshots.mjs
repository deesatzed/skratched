#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(new URL("..", import.meta.url).pathname);
const ASSET_DIR = join(ROOT, "docs", "assets");
const CHROME_CANDIDATES = [
  process.env.SKRATCHED_CHROME,
  "/Users/o2satz/Library/Caches/ms-playwright/chromium-1200/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
].filter(Boolean);

const chrome = CHROME_CANDIDATES.find((candidate) => existsSync(candidate));
if (!chrome) {
  throw new Error("No Chromium/Chrome executable found. Set SKRATCHED_CHROME.");
}

const delay = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

async function waitForJson(url, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
      lastError = new Error(`${response.status} ${response.statusText}`);
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message || "unknown"}`);
}

async function postJson(baseUrl, path, payload) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`${path} failed: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function seedDemo(baseUrl) {
  const project = "readme-demo";
  await postJson(baseUrl, "/api/capture", {
    project,
    source: "manual",
    text: "OpenRouter key belongs with the local model-routing experiment, the proxy config, and the June release checklist.",
  });
  await postJson(baseUrl, "/api/capture", {
    project,
    source: "clipboard",
    text: "OPENROUTER_API_KEY=sk-or-v1-readmedemoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Browser-safe fake key",
  });
  await postJson(baseUrl, "/api/capture", {
    project,
    source: "manual",
    text: "Prompt: compare the latest local retrieval notes, API key context, and release blockers before drafting the handoff.",
  });
  await postJson(baseUrl, "/api/capture", {
    project,
    source: "manual",
    text: "select user_id, max(created_at) from audit_log where vendor = 'openrouter' group by user_id;",
  });
  await postJson(baseUrl, "/api/capture-file", {
    project,
    source: "screenshot-work",
    filename: "Screenshot OpenRouter Settings.png",
    media_type: "image/png",
    content_base64: "iVBORw0KGgpzYWZlLXJlYWRtZS1kZW1vLXBuZw==",
  });
}

async function seedScoutWorkspace(tmp) {
  const root = join(tmp, "workspace-scout-demo");
  const project = join(root, "model-gateway");
  await mkdir(project, { recursive: true });
  await writeFile(join(project, ".env"), "OPENROUTER_API_KEY=sk-or-v1-screenshotdemoaaaaaaaaaaaaaaaaaaaa\n");
  await writeFile(join(project, "settings.toml"), "[models]\nprimary='local'\n");
  await writeFile(join(project, "release-notes.md"), "# Release notes\nWorkspace Scout should preview this file.\n");
  return root;
}

async function connectCdp(debugPort) {
  const version = await waitForJson(`http://127.0.0.1:${debugPort}/json/version`);
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolveOpen, rejectOpen) => {
    ws.addEventListener("open", resolveOpen, { once: true });
    ws.addEventListener("error", rejectOpen, { once: true });
  });
  let nextId = 1;
  const pending = new Map();
  ws.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const { resolve: resolvePending, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(`${message.error.message}: ${message.error.data || ""}`));
    else resolvePending(message);
  });
  function send(method, params = {}, sessionId = undefined) {
    const id = nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    ws.send(JSON.stringify(payload));
    return new Promise((resolveSend, reject) => {
      pending.set(id, { resolve: resolveSend, reject });
      setTimeout(() => {
        if (!pending.has(id)) return;
        pending.delete(id);
        reject(new Error(`CDP timeout: ${method}`));
      }, 10000);
    });
  }
  return { ws, send };
}

async function run() {
  const tmp = await mkdtemp(join(tmpdir(), "skratched-readme-shots-"));
  const port = 8880 + Math.floor(Math.random() * 800);
  const debugPort = 9880 + Math.floor(Math.random() * 800);
  const baseUrl = `http://127.0.0.1:${port}`;
  const dbPath = join(tmp, "skratched.db");
  const profilePath = join(tmp, "chrome-profile");
  const server = spawn("python", ["server.py", "--host", "127.0.0.1", "--port", String(port), "--db", dbPath], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const chromeProcess = spawn(chrome, [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-background-networking",
    "--disable-sync",
    "--no-first-run",
    "--no-default-browser-check",
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${profilePath}`,
    "about:blank",
  ], { stdio: ["ignore", "pipe", "pipe"] });

  let ws;
  try {
    await waitForJson(`${baseUrl}/api/health`);
    await seedDemo(baseUrl);
    const scoutRoot = await seedScoutWorkspace(tmp);
    const { ws: connectedWs, send } = await connectCdp(debugPort);
    ws = connectedWs;
    const target = await send("Target.createTarget", { url: "about:blank" });
    const attach = await send("Target.attachToTarget", {
      targetId: target.result.targetId,
      flatten: true,
    });
    const sessionId = attach.result.sessionId;
    const evaluate = async (expression) => {
      const response = await send("Runtime.evaluate", {
        expression,
        awaitPromise: true,
        returnByValue: true,
      }, sessionId);
      if (response.result?.exceptionDetails) {
        throw new Error(response.result.exceptionDetails.text || "Runtime exception");
      }
      return response.result?.result?.value;
    };
    const waitFor = async (expression) => {
      const deadline = Date.now() + 8000;
      while (Date.now() < deadline) {
        if (await evaluate(expression)) return;
        await delay(100);
      }
      throw new Error(`Timed out waiting for ${expression}`);
    };
    const screenshot = async (name) => {
      const result = await send("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: true,
        fromSurface: true,
      }, sessionId);
      await writeFile(join(ASSET_DIR, name), Buffer.from(result.result.data, "base64"));
    };

    await mkdir(ASSET_DIR, { recursive: true });
    await send("Page.enable", {}, sessionId);
    await send("Runtime.enable", {}, sessionId);
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: 1100,
      deviceScaleFactor: 1,
      mobile: false,
    }, sessionId);

    await send("Page.navigate", { url: baseUrl }, sessionId);
    await waitFor("document.readyState === 'complete' && document.querySelectorAll('#recent article.item').length >= 4");
    await screenshot("skratched-workspace.png");

    await evaluate(`document.querySelector('#scoutRootInput').value = ${JSON.stringify(scoutRoot)}`);
    await evaluate("document.querySelector('#scoutTypeInput').value = 'all'");
    await evaluate("document.querySelector('#scoutSinceInput').value = ''");
    await evaluate("document.querySelector('#scoutDepthInput').value = '3'");
    await evaluate("document.querySelector('#workspaceScoutButton').click()");
    await waitFor("(document.querySelector('#results')?.innerText || '').includes('Workspace Scout') && (document.querySelector('#results')?.innerText || '').includes('settings.toml')");
    await screenshot("skratched-workspace-scout.png");

    await evaluate("document.querySelector('#searchInput').value = 'find my last OpenRouter API keys added in the last 3 weeks'");
    await evaluate("document.querySelector('#searchInput').dispatchEvent(new Event('input', { bubbles: true }))");
    await evaluate("document.querySelector('#searchButton').click()");
    await waitFor("document.querySelectorAll('#results article.item button[data-context]').length >= 1");
    await evaluate("document.querySelector('#results article.item button[data-context]').click()");
    await waitFor("(document.querySelector('#results')?.innerText || '').includes('context_chain')");
    await screenshot("skratched-context-map.png");

    await evaluate("document.querySelector('#exportButton').click()");
    await waitFor("(document.querySelector('#results')?.innerText || '').includes('JSONL export ready')");
    await screenshot("skratched-redacted-export.png");

    console.log(JSON.stringify({
      schema: "skratched.readme_screenshots.v1",
      ok: true,
      assets: [
        "docs/assets/skratched-workspace.png",
        "docs/assets/skratched-workspace-scout.png",
        "docs/assets/skratched-context-map.png",
        "docs/assets/skratched-redacted-export.png",
      ],
    }, null, 2));
  } finally {
    try { ws?.close(); } catch {}
    server.kill("SIGTERM");
    chromeProcess.kill("SIGTERM");
    await delay(300);
    try { server.kill("SIGKILL"); } catch {}
    try { chromeProcess.kill("SIGKILL"); } catch {}
    await rm(tmp, { recursive: true, force: true });
  }
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
