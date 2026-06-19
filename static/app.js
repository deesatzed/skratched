const state = {
  items: [],
  categories: [],
  tags: [],
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error || "request failed");
    error.payload = payload;
    throw error;
  }
  return payload;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderMemoryMap(map) {
  if (!map) return "";
  const edgeTypes = Object.entries(map.summary.edge_types || {})
    .map(([type, count]) => `<span class="map-chip">${escapeHtml(type)} ${escapeHtml(count)}</span>`)
    .join("");
  const categories = Object.entries(map.summary.categories || {})
    .map(([category, count]) => `<span class="map-chip">${escapeHtml(category)} ${escapeHtml(count)}</span>`)
    .join("");
  const hints = (map.hints || [])
    .map((hint) => `<div class="map-hint">${escapeHtml(hint)}</div>`)
    .join("");
  const clusters = (map.clusters || [])
    .map((cluster) => {
      const items = (cluster.items || [])
        .map((item) => `<li><span>${escapeHtml(item.category)}</span>${escapeHtml(item.preview || item.summary || item.id)}</li>`)
        .join("");
      return `
        <section class="map-cluster">
          <div class="map-cluster-title">${escapeHtml(cluster.name)} <span>${escapeHtml(cluster.count)}</span></div>
          <ul>${items}</ul>
        </section>
      `;
    })
    .join("");
  return `
    <div class="memory-map">
      <div class="map-row">
        <span class="map-chip strong">${escapeHtml(map.summary.node_count)} nodes</span>
        <span class="map-chip strong">${escapeHtml(map.summary.edge_count)} links</span>
        ${edgeTypes}
        ${categories}
      </div>
      ${hints ? `<div class="map-hints">${hints}</div>` : ""}
      ${clusters || `<div class="meta">No related clusters yet.</div>`}
    </div>
  `;
}

function renderFilingSuggestion(item) {
  const suggestion = item.filing_suggestion;
  if (!suggestion) return "";
  const pending = suggestion.status === "pending";
  return `
    <div class="filing-suggestion ${pending ? "pending" : ""}">
      <div>
        <strong>${pending ? "Suggested shelf" : "Filed from suggestion"}</strong>
        <span>${escapeHtml(suggestion.target_category)} · ${escapeHtml(suggestion.confidence || "unknown")}</span>
      </div>
      <p>${escapeHtml(suggestion.reason || "suggested filing")}</p>
      ${pending ? `<button class="secondary" type="button" data-accept-filing="${escapeHtml(item.id)}">Accept</button>` : ""}
    </div>
  `;
}

function renderTags(item) {
  const tags = item.tags || item.facets?.tags || [];
  if (!tags.length) return "";
  return `<div class="tag-row">${tags.map((tag) => `<span class="tag-chip">${escapeHtml(tag)}</span>`).join("")}</div>`;
}

function renderNextSuggestions(item) {
  const suggestions = item.next_suggestions || [];
  if (!suggestions.length) return "";
  return `
    <div class="next-suggestions" aria-label="Likely next actions">
      ${suggestions
        .map(
          (suggestion) => `
            <div class="next-chip" title="${escapeHtml(suggestion.reason || "")}">
              <strong>${escapeHtml(suggestion.label || suggestion.type)}</strong>
              <span>${escapeHtml(suggestion.reason || "")}</span>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function itemCard(item) {
  const associated = (item.associated || [])
    .map((entry) => `<div class="associated">${escapeHtml(entry.preview)}</div>`)
    .join("");
  const why = (item.why || []).map((reason) => escapeHtml(reason)).join(" · ");
  const scores = item.scores
    ? `exact ${item.scores.exact} · metadata ${item.scores.metadata} · semantic ${item.scores.semantic}`
    : "";
  const replacement = item.deprecated
    ? `<div class="warning">Deprecated · use ${escapeHtml((item.successor && (item.successor.preview || item.successor.summary)) || item.successor_id || "successor")} ${item.replacement_reason ? `· ${escapeHtml(item.replacement_reason)}` : ""}</div>`
    : "";
  const reveal = item.sensitivity === "sensitive"
    ? `<div class="item-actions"><button class="secondary" type="button" data-reveal="${escapeHtml(item.id)}">Reveal</button></div>`
    : "";
  const actions = `
    <div class="item-actions">
      <button class="secondary" type="button" data-context="${escapeHtml(item.id)}">Context</button>
      <button class="secondary" type="button" data-refile="${escapeHtml(item.id)}">File</button>
      <button class="secondary" type="button" data-tags="${escapeHtml(item.id)}">Tags</button>
      <button class="secondary" type="button" data-undo-filing="${escapeHtml(item.id)}">Undo Filing</button>
      <button class="secondary" type="button" data-reuse="${escapeHtml(item.id)}">Reuse</button>
      <button class="secondary" type="button" data-edit="${escapeHtml(item.id)}">Edit</button>
      <button class="secondary" type="button" data-replace="${escapeHtml(item.id)}">Replace</button>
    </div>
  `;
  return `
    <article class="item">
      <header>
        <span class="badge ${item.sensitivity === "sensitive" ? "sensitive" : ""}">${escapeHtml(item.category)}</span>
        <span class="meta">${escapeHtml(item.created_at || "")}</span>
      </header>
      <div class="preview">${escapeHtml(item.preview || item.summary || "")}</div>
      ${renderTags(item)}
      ${renderFilingSuggestion(item)}
      ${renderNextSuggestions(item)}
      ${renderMemoryMap(item.memory_map)}
      ${replacement}
      ${why ? `<div class="meta">${why}</div>` : ""}
      ${scores ? `<div class="meta">${escapeHtml(scores)}</div>` : ""}
      ${associated}
      ${reveal}
      ${actions}
    </article>
  `;
}

function renderItems(target, items) {
  $(target).innerHTML = items.length ? items.map(itemCard).join("") : `<div class="meta">No items yet.</div>`;
}

function renderCategories() {
  const defaults = ["prompts", "SQL queries", "API-Keys", "screenshots-work", "screenshots-products", "code", "commands", "research", "follow-up"];
  const live = state.categories.map((c) => c.category);
  const merged = Array.from(new Set([...live, ...defaults]));
  $("categoryChips").innerHTML = merged
    .map((category) => `<button class="chip secondary" type="button" data-category="${escapeHtml(category)}">${escapeHtml(category)}</button>`)
    .join("");
}

function renderLikelyNext() {
  const latest = state.items[0];
  const hints = [];
  if (latest?.category === "API-Keys") hints.push("Associated notes and recent project context are prioritized for key searches.");
  if (latest?.family_id) hints.push(`Duplicate family ${latest.family_id.slice(0, 12)} is tracked.`);
  if (state.tags.length) hints.push(`Top tag ${state.tags[0].tag} appears on ${state.tags[0].count} item${state.tags[0].count === 1 ? "" : "s"}.`);
  if (!hints.length) hints.push("Recent project, category, duplicates, and linked context will appear here.");
  $("likelyNext").innerHTML = hints.map((hint) => `<div class="hint">${escapeHtml(hint)}</div>`).join("");
}

async function refresh() {
  const [health, items, categories, tags] = await Promise.all([
    api("/api/health"),
    api("/api/items"),
    api("/api/categories"),
    api("/api/tags"),
  ]);
  state.items = items.items;
  state.categories = categories.categories;
  state.tags = tags.tags;
  $("health").textContent = `${health.items} items · ${health.events} events · local SQLite`;
  renderItems("recent", state.items);
  renderCategories();
  renderLikelyNext();
}

async function capture() {
  const text = $("captureText").value;
  const project = $("projectInput").value;
  const source = $("sourceInput").value;
  const filingMode = $("filingModeInput").value;
  if (!text.trim()) return;
  const payload = await api("/api/capture", {
    method: "POST",
    body: JSON.stringify({ text, project, source, filing_mode: filingMode }),
  });
  $("captureText").value = "";
  await refresh();
  renderItems("results", [payload.item]);
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      const value = String(reader.result || "");
      resolve(value.includes(",") ? value.split(",").pop() : value);
    });
    reader.addEventListener("error", () => reject(reader.error || new Error("file read failed")));
    reader.readAsDataURL(file);
  });
}

async function captureFiles(fileList) {
  const files = Array.from(fileList || []);
  if (!files.length) return;
  const project = $("projectInput").value;
  const source = $("sourceInput").value.startsWith("screenshot") ? $("sourceInput").value : "file-drop";
  const captured = [];
  for (const file of files) {
    const contentBase64 = await fileToBase64(file);
    const payload = await api("/api/capture-file", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        media_type: file.type || "application/octet-stream",
        content_base64: contentBase64,
        source,
        project,
      }),
    });
    captured.push(payload.item);
  }
  await refresh();
  renderItems("results", captured);
}

async function search() {
  const q = $("searchInput").value.trim();
  if (!q) return;
  const payload = await api(`/api/search?q=${encodeURIComponent(q)}`);
  renderItems("results", payload.results);
}

async function exportPreview() {
  const payload = await api("/api/export/jsonl", {
    method: "POST",
    body: JSON.stringify({ label: "ui-jsonl-preview" }),
  });
  renderItems("results", [
    {
      category: "safe_exports",
      sensitivity: "safe",
      preview: `JSONL export ready: ${payload.item_count} items\nbundle_hash=${payload.bundle_hash}\n\n${payload.jsonl}`,
      created_at: new Date().toISOString(),
      why: ["redacted previews only", "JSONL manifest generated", "hash verified"],
    },
  ]);
  await refresh();
}

async function revealItem(itemId) {
  const reason = window.prompt("Reason");
  if (!reason) return;
  const ok = window.confirm("Reveal sensitive value locally?");
  if (!ok) return;
  const payload = await api("/api/reveal", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, local_unlock: true, reason }),
  });
  renderItems("results", [
    {
      ...payload.item,
      preview: payload.item.content,
      why: ["local unlock", "reveal event recorded"],
    },
  ]);
}

async function importBundle() {
  const raw = window.prompt("Paste redacted bundle JSON or JSONL");
  if (!raw) return;
  const isJsonl = raw.trim().includes("\n");
  let preview;
  try {
    preview = isJsonl
      ? await api("/api/import/jsonl/preview", {
          method: "POST",
          body: JSON.stringify({ jsonl: raw }),
        })
      : await api("/api/import/preview", {
          method: "POST",
          body: raw,
        });
  } catch (error) {
    renderItems("results", [diagnosticCard(error.payload && error.payload.diagnostic, error.message)]);
    return;
  }
  const lines = preview.entries
    .slice(0, 8)
    .map((entry) => `${entry.action} · ${entry.category} · ${entry.preview || entry.content_hash}`)
    .join("\n");
  renderItems("results", [
    {
      category: "safe_import_preview",
      sensitivity: "safe",
      preview: `Import preview: ${preview.importable_count} importable, ${preview.duplicate_count} duplicate/skipped\n${lines}`,
      created_at: new Date().toISOString(),
      why: ["hash verified", "preview before apply", "duplicates skipped"],
    },
  ]);
  if (!preview.importable_count) {
    return;
  }
  const ok = window.confirm(`Import ${preview.importable_count} redacted item metadata records?`);
  if (!ok) return;
  let report;
  try {
    report = isJsonl
      ? await api("/api/import/jsonl", {
          method: "POST",
          body: JSON.stringify({ jsonl: raw }),
        })
      : await api("/api/import/redacted", {
          method: "POST",
          body: raw,
        });
  } catch (error) {
    renderItems("results", [diagnosticCard(error.payload && error.payload.diagnostic, error.message)]);
    return;
  }
  renderItems("results", [
    {
      category: "safe_import",
      sensitivity: "safe",
      preview: `Imported ${report.imported} redacted item metadata records. Skipped ${report.skipped}.`,
      created_at: new Date().toISOString(),
      why: ["hash verified", "redacted bundle only"],
    },
  ]);
  await refresh();
}

function diagnosticCard(diagnostic, error) {
  const retryOptions = (diagnostic && diagnostic.retry_options) || [];
  const storageOk = diagnostic && diagnostic.storage && diagnostic.storage.ok;
  const ftsOk = diagnostic && diagnostic.indexes && diagnostic.indexes.fts && diagnostic.indexes.fts.ok;
  const redactionOk = diagnostic && diagnostic.redaction && diagnostic.redaction.ok;
  return {
    id: "diagnostic",
    category: "diagnostic",
    sensitivity: "safe",
    preview: `${(diagnostic && diagnostic.operation) || "operation"} failed: ${error}`,
    created_at: new Date().toISOString(),
    why: [
      `storage: ${storageOk ? "ok" : "check"}`,
      `fts: ${ftsOk ? "ok" : "check"}`,
      `redaction: ${redactionOk ? "ok" : "check"}`,
      ...retryOptions,
    ],
  };
}

async function createShelf() {
  const category = window.prompt("Shelf name");
  if (!category) return;
  const reason = window.prompt("Reason") || "manual shelf";
  const payload = await api("/api/shelves", {
    method: "POST",
    body: JSON.stringify({ category, reason }),
  });
  state.categories = payload.categories;
  renderCategories();
  renderItems("results", [
    {
      category: "shelf",
      sensitivity: "safe",
      preview: `Shelf ready: ${payload.shelf.category}`,
      created_at: new Date().toISOString(),
      why: ["idempotent shelf creation", reason],
    },
  ]);
}

async function scanScreenshots() {
  const directory = window.prompt("Screenshot folder path", "");
  if (directory === null) return;
  const project = $("projectInput").value;
  const payload = await api("/api/screenshots/scan", {
    method: "POST",
    body: JSON.stringify({ directory: directory || "", project, limit: 10 }),
  });
  const imported = payload.items || [];
  if (imported.length) {
    renderItems("results", imported.map((item) => ({
      ...item,
      why: ["screenshot watch import", `${payload.skipped_count} duplicate skipped`],
    })));
  } else {
    renderItems("results", [
      {
        category: "screenshots-work",
        sensitivity: "safe",
        preview: `Screenshot scan found no new files in ${payload.directory}. Skipped ${payload.skipped_count}.`,
        created_at: new Date().toISOString(),
        why: ["screenshot watch scan", "duplicates are skipped by byte hash"],
      },
    ]);
  }
  await refresh();
}

function graphCard(graph) {
  const status = graph.root.deprecated ? `Deprecated -> ${graph.root.successor_id.slice(0, 8)}` : "Active";
  return {
    id: graph.root.id,
    category: "context_chain",
    sensitivity: "safe",
    preview: `${status} · ${graph.summary.node_count} memory items · ${graph.summary.edge_count} links`,
    created_at: new Date().toISOString(),
    why: ["associated links", "duplicate family", "replacement chain", "memory map"],
    memory_map: {
      summary: graph.summary,
      clusters: graph.clusters,
      hints: graph.memory_hints,
    },
  };
}

async function showContext(itemId) {
  const graph = await api(`/api/context?item_id=${encodeURIComponent(itemId)}`);
  renderItems("results", [graphCard(graph)]);
}

async function replaceItem(oldItemId) {
  const newItemId = window.prompt("Successor item ID");
  if (!newItemId) return;
  const reason = window.prompt("Reason") || "replacement";
  const graph = await api("/api/replace", {
    method: "POST",
    body: JSON.stringify({ old_item_id: oldItemId, new_item_id: newItemId, reason }),
  });
  renderItems("results", [graphCard(graph)]);
  await refresh();
}

async function editItem(itemId) {
  const text = window.prompt("New item content");
  if (text === null || !text.trim()) return;
  const reason = window.prompt("Reason") || "edit";
  const payload = await api("/api/items/edit", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, text, reason }),
  });
  renderItems("results", [
    {
      ...payload.item,
      why: ["version successor created", reason],
    },
  ]);
  await refresh();
}

function actionCardItem(card) {
  return {
    id: card.action_id,
    category: `action:${card.risk_class}`,
    sensitivity: card.risk_class === "safe" ? "safe" : "sensitive",
    preview: `${card.action} · ${card.decision}`,
    created_at: "local safety check",
    why: card.checks.map((check) => `${check.name}: ${check.detail}`),
    associated: [
      {
        preview: card.apply_allowed
          ? "Skratched records approval only; it does not execute item content."
          : "Blocked items cannot be applied from Skratched.",
      },
    ],
    next_suggestions: [
      {
        type: "risk_review",
        label: card.requires_approval ? "Approval required" : "Allowed",
        reason: (card.risk_reasons || []).join("; ") || "local-only reuse check",
      },
    ],
  };
}

async function reuseItem(itemId) {
  const checked = await api("/api/actions/check", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, action: "reuse" }),
  });
  if (!checked.apply_allowed) {
    renderItems("results", [actionCardItem(checked)]);
    return;
  }
  const approved = !checked.requires_approval || window.confirm("Approve this local reuse record?");
  if (!approved) {
    renderItems("results", [actionCardItem(checked)]);
    return;
  }
  const applied = await api("/api/actions/apply", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, action: "reuse", approved, reason: "browser reuse approval" }),
  });
  renderItems("results", [actionCardItem(applied)]);
  await refresh();
}

async function refileItem(itemId) {
  const category = window.prompt("Category");
  if (!category) return;
  const reason = window.prompt("Reason") || "manual filing";
  const payload = await api("/api/refile", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, category, reason }),
  });
  renderItems("results", [
    {
      ...payload.item,
      why: ["manual filing applied", reason],
    },
  ]);
  await refresh();
}

async function editTags(itemId) {
  const current = state.items.find((item) => item.id === itemId)?.tags || [];
  const raw = window.prompt("Tags", current.join(", "));
  if (raw === null) return;
  const reason = window.prompt("Reason") || "tag edit";
  const payload = await api("/api/tags", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, tags: raw.split(","), reason }),
  });
  renderItems("results", [
    {
      ...payload.item,
      why: ["tags updated", reason],
    },
  ]);
  await refresh();
}

async function acceptFilingSuggestion(itemId) {
  const reason = window.prompt("Reason") || "accept filing suggestion";
  const payload = await api("/api/filing-suggestions/accept", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, reason }),
  });
  renderItems("results", [
    {
      ...payload.item,
      why: ["filing suggestion accepted", reason],
    },
  ]);
  await refresh();
}

async function undoFiling(itemId) {
  const reason = window.prompt("Reason") || "undo filing";
  const payload = await api("/api/undo-filing", {
    method: "POST",
    body: JSON.stringify({ item_id: itemId, reason }),
  });
  renderItems("results", [
    {
      ...payload.item,
      why: ["filing restored", reason],
    },
  ]);
  await refresh();
}

async function showReplacements() {
  const payload = await api("/api/replacements");
  const cards = payload.replacements.map((entry) => ({
    id: entry.old.id,
    category: "replacement",
    sensitivity: "safe",
    preview: `Deprecated\n${entry.old.preview || entry.old.summary}\n\nUse\n${entry.new.preview || entry.new.summary}`,
    created_at: entry.created_at,
    why: [entry.relation, entry.reason],
    deprecated: true,
    successor_id: entry.new.id,
    successor: entry.new,
    replacement_reason: entry.reason,
  }));
  renderItems("results", cards);
}

document.addEventListener("click", (event) => {
  const revealButton = event.target.closest("button[data-reveal]");
  if (revealButton) {
    revealItem(revealButton.dataset.reveal);
    return;
  }
  const contextButton = event.target.closest("button[data-context]");
  if (contextButton) {
    showContext(contextButton.dataset.context);
    return;
  }
  const replaceButton = event.target.closest("button[data-replace]");
  if (replaceButton) {
    replaceItem(replaceButton.dataset.replace);
    return;
  }
  const editButton = event.target.closest("button[data-edit]");
  if (editButton) {
    editItem(editButton.dataset.edit);
    return;
  }
  const refileButton = event.target.closest("button[data-refile]");
  if (refileButton) {
    refileItem(refileButton.dataset.refile);
    return;
  }
  const tagsButton = event.target.closest("button[data-tags]");
  if (tagsButton) {
    editTags(tagsButton.dataset.tags);
    return;
  }
  const reuseButton = event.target.closest("button[data-reuse]");
  if (reuseButton) {
    reuseItem(reuseButton.dataset.reuse);
    return;
  }
  const undoFilingButton = event.target.closest("button[data-undo-filing]");
  if (undoFilingButton) {
    undoFiling(undoFilingButton.dataset.undoFiling);
    return;
  }
  const acceptFilingButton = event.target.closest("button[data-accept-filing]");
  if (acceptFilingButton) {
    acceptFilingSuggestion(acceptFilingButton.dataset.acceptFiling);
    return;
  }
  const button = event.target.closest("button[data-category]");
  if (!button) return;
  $("searchInput").value = button.dataset.category;
  search();
});

$("captureButton").addEventListener("click", capture);
$("fileButton").addEventListener("click", () => $("fileInput").click());
$("fileInput").addEventListener("change", async (event) => {
  await captureFiles(event.target.files);
  event.target.value = "";
});
$("searchButton").addEventListener("click", search);
$("refreshButton").addEventListener("click", refresh);
$("exportButton").addEventListener("click", exportPreview);
$("importButton").addEventListener("click", importBundle);
$("shelfButton").addEventListener("click", createShelf);
$("scanScreenshotsButton").addEventListener("click", scanScreenshots);
$("replacementsButton").addEventListener("click", showReplacements);
$("captureText").addEventListener("dragover", (event) => {
  event.preventDefault();
  $("captureText").classList.add("is-dragging");
});
$("captureText").addEventListener("dragleave", () => {
  $("captureText").classList.remove("is-dragging");
});
$("captureText").addEventListener("drop", async (event) => {
  event.preventDefault();
  $("captureText").classList.remove("is-dragging");
  if (event.dataTransfer?.files?.length) {
    await captureFiles(event.dataTransfer.files);
  }
});
$("captureText").addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
    capture();
  }
});
$("searchInput").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    search();
  }
});

refresh().catch((error) => {
  $("health").textContent = error.message;
});
