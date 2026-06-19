#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);

function readArg(name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

const baseUrl = readArg("--base-url", process.env.SKRATCHED_BASE_URL || "http://127.0.0.1:8787");
const explicitChrome = readArg("--chrome", process.env.SKRATCHED_CHROME || "");
const candidates = [
  explicitChrome,
  "/Users/o2satz/Library/Caches/ms-playwright/chromium-1200/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
].filter(Boolean);
const chrome = candidates.find((candidate) => existsSync(candidate));
if (!chrome) {
  throw new Error("No Chromium/Chrome executable found. Set SKRATCHED_CHROME or pass --chrome.");
}

const port = Number(readArg("--debug-port", "0")) || 9223 + Math.floor(Math.random() * 1000);
const profile = await mkdtemp(join(tmpdir(), "skratched-cdp-"));
const child = spawn(chrome, [
  "--headless=new",
  "--no-sandbox",
  "--disable-gpu",
  "--disable-background-networking",
  "--disable-sync",
  "--no-first-run",
  "--no-default-browser-check",
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`,
  "about:blank",
], { stdio: ["ignore", "pipe", "pipe"] });

let stderr = "";
child.stderr.on("data", (chunk) => {
  stderr += chunk.toString();
});

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function waitForVersion() {
  const deadline = Date.now() + 10000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await fetchJson(`http://127.0.0.1:${port}/json/version`);
    } catch (error) {
      lastError = error;
      await delay(100);
    }
  }
  throw new Error(`Chrome DevTools did not start: ${lastError?.message || "timeout"}\n${stderr}`);
}

let ws;
let pageSession;
let nextId = 1;
const pending = new Map();

function send(method, params = {}, sessionId = undefined) {
  const id = nextId++;
  const payload = { id, method, params };
  if (sessionId) payload.sessionId = sessionId;
  ws.send(JSON.stringify(payload));
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error(`CDP timeout: ${method}`));
      }
    }, 10000);
  });
}

async function evaluate(expression) {
  const result = await send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  }, pageSession);
  if (result.result?.exceptionDetails) {
    throw new Error(result.result.exceptionDetails.text || "Runtime exception");
  }
  const value = result.result?.result;
  if (value?.subtype === "error") {
    throw new Error(value.description || "Runtime error");
  }
  return value?.value;
}

async function waitFor(expression, timeout = 7000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try {
      last = await evaluate(expression);
      if (last) return last;
    } catch (error) {
      last = error.message;
    }
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${expression}; last=${last}`);
}

async function setValue(selector, value) {
  await evaluate(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) throw new Error("missing ${selector}");
    el.value = ${JSON.stringify(value)};
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  })()`);
}

async function click(selector) {
  await evaluate(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) throw new Error("missing ${selector}");
    el.click();
    return true;
  })()`);
}

function failedChecks(checks) {
  return checks.filter((check) => (
    check.rawKeyVisible ||
    check.hasApiKeysCategory === false ||
    check.hasRedaction === false ||
    check.hasContextButton === false ||
    check.hasContextChain === false ||
    check.hasMemoryMap === false
  ));
}

try {
  const version = await waitForVersion();
  ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", reject, { once: true });
  });
  ws.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(`${message.error.message}: ${message.error.data || ""}`));
    else resolve(message);
  });

  const target = await send("Target.createTarget", { url: "about:blank" });
  const attach = await send("Target.attachToTarget", {
    targetId: target.result.targetId,
    flatten: true,
  });
  pageSession = attach.result.sessionId;
  await send("Page.enable", {}, pageSession);
  await send("Runtime.enable", {}, pageSession);

  await send("Page.navigate", { url: baseUrl }, pageSession);
  await waitFor("document.readyState === 'complete' && !!document.querySelector('#captureText')");
  await waitFor("document.querySelector('#health')?.textContent.includes('local SQLite')");

  const suffix = Date.now().toString(36);
  const rawKey = `sk-or-v1-${suffix}${"a".repeat(48)}`;
  const checks = [];
  checks.push({
    name: "loaded",
    title: await evaluate("document.title"),
    health: await evaluate("document.querySelector('#health')?.textContent"),
  });

  await setValue("#projectInput", `ui-smoke-${suffix}`);
  await setValue(
    "#captureText",
    `Associated context note for Browser UI smoke ${suffix}: OpenRouter key belongs with recent model gateway testing.`,
  );
  await click("#captureButton");
  await waitFor("document.querySelector('#captureText')?.value === ''");

  await setValue("#projectInput", `ui-smoke-${suffix}`);
  await setValue("#captureText", `OPENROUTER_API_KEY=${rawKey} Browser UI smoke ${suffix}`);
  await click("#captureButton");
  await waitFor("document.querySelector('#captureText')?.value === ''");
  await waitFor("document.querySelectorAll('#results article.item').length >= 1");
  const captureText = await evaluate("document.querySelector('#results')?.innerText || ''");
  checks.push({
    name: "capture_result_redacted",
    hasApiKeysCategory: captureText.includes("API-Keys"),
    hasRedaction: captureText.includes("[REDACTED:openrouter_key]"),
    rawKeyVisible: captureText.includes(rawKey),
  });

  await setValue("#searchInput", "find my last OpenRouter API keys added in the last 3 weeks");
  await click("#searchButton");
  await waitFor("document.querySelectorAll('#results article.item button[data-context]').length >= 1");
  const searchText = await evaluate("document.querySelector('#results')?.innerText || ''");
  checks.push({
    name: "search_flow",
    resultCount: await evaluate("document.querySelectorAll('#results article.item').length"),
    hasContextButton: await evaluate("!!document.querySelector('#results article.item button[data-context]')"),
    hasWhy: searchText.includes("matched") || searchText.includes("exact") || searchText.includes("metadata"),
    rawKeyVisible: searchText.includes(rawKey),
  });

  await click("#results article.item button[data-context]");
  await waitFor("(document.querySelector('#results')?.innerText || '').includes('context_chain')");
  const contextText = await evaluate("document.querySelector('#results')?.innerText || ''");
  checks.push({
    name: "context_view",
    hasContextChain: contextText.includes("context_chain"),
    hasMemoryMap: contextText.includes("nodes") && contextText.includes("links"),
    hasClusterOrHint: (
      contextText.includes("linked") ||
      contextText.includes("chronological") ||
      contextText.includes("nearby") ||
      contextText.includes("recent")
    ),
    rawKeyVisible: contextText.includes(rawKey),
  });

  const dom = await evaluate("document.documentElement.outerHTML");
  checks.push({ name: "dom_secret_leak", rawKeyVisible: dom.includes(rawKey) });

  const failed = failedChecks(checks);
  console.log(JSON.stringify({
    schema: "skratched.browser_smoke.v1",
    ok: failed.length === 0,
    base_url: baseUrl,
    suffix,
    checks,
    failed,
  }, null, 2));
  process.exitCode = failed.length === 0 ? 0 : 1;
} finally {
  try {
    ws?.close();
  } catch {}
  child.kill("SIGTERM");
  await delay(300);
  try {
    child.kill("SIGKILL");
  } catch {}
  await rm(profile, { recursive: true, force: true });
}
