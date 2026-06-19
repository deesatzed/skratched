from __future__ import annotations

import json
import mimetypes
import os
import sqlite3
import time
import uuid
import hashlib
import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .ai import run_optional_ai_analysis
from .analyze import analyze_capture, redact_text, utc_now_iso
from .semantic import local_semantic_signal


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _normalize_tag(value: Any) -> str:
    tag = str(value).strip().lower()
    tag = re.sub(r"\s+", "-", tag)
    tag = re.sub(r"[^a-z0-9_./-]+", "", tag)
    tag = tag.strip("-._/")
    return tag[:64]


NEAR_DUPLICATE_STOP_WORDS = {
    "a",
    "an",
    "and",
    "as",
    "export",
    "for",
    "in",
    "of",
    "the",
    "to",
    "with",
}


WORKSPACE_SCOUT_PRESETS = {
    "secrets": {".env", ".key", ".pem", ".p12", ".pfx", ".secret"},
    "configs": {".yaml", ".yml", ".toml", ".json", ".ini", ".conf"},
    "code": {".rs", ".ts", ".tsx", ".py", ".go", ".js", ".jsx", ".mjs", ".cjs", ".sh"},
    "screenshots": {".png", ".jpg", ".jpeg", ".webp", ".gif"},
    "docs": {".md", ".txt", ".rst", ".pdf", ".docx"},
}

WORKSPACE_SCOUT_SKIP_DIRS = {".git", ".next", "__pycache__", "node_modules", "target", ".venv", "venv"}


def _workspace_file_ext(path: Path) -> str:
    name = path.name.lower()
    if name.startswith(".") and "." not in name[1:]:
        return name
    return path.suffix.lower()


def _workspace_type_label(path: Path) -> str:
    ext = _workspace_file_ext(path)
    for label, extensions in WORKSPACE_SCOUT_PRESETS.items():
        if ext in extensions:
            return label
    return "other"


def _workspace_matches_type(path: Path, type_spec: str | None) -> bool:
    if not type_spec or type_spec == "all":
        return True
    ext = _workspace_file_ext(path)
    if type_spec in WORKSPACE_SCOUT_PRESETS:
        return ext in WORKSPACE_SCOUT_PRESETS[type_spec]
    return any(ext == part.strip().lower() for part in type_spec.split(",") if part.strip())


def _parse_workspace_time(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip().lower()
    now = datetime.now(timezone.utc)
    try:
        if raw.endswith("m"):
            return now - timedelta(minutes=int(raw[:-1]))
        if raw.endswith("h"):
            return now - timedelta(hours=int(raw[:-1]))
        if raw.endswith("d"):
            return now - timedelta(days=int(raw[:-1]))
        parsed = datetime.fromisoformat(raw.replace("z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError("time values must use 30m, 2h, 7d, or ISO format") from exc


def _system_timestamp_to_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _near_duplicate_terms(text: str) -> set[str]:
    redacted = redact_text(text)
    terms = set(re.findall(r"[a-z0-9_]+", redacted.lower()))
    return {term for term in terms if len(term) > 2 and term not in NEAR_DUPLICATE_STOP_WORDS}


def _near_duplicate_score(left: str, right: str) -> float:
    left_terms = _near_duplicate_terms(left)
    right_terms = _near_duplicate_terms(right)
    if len(left_terms) < 3 or len(right_terms) < 3:
        return 0.0
    overlap = left_terms & right_terms
    if len(overlap) < 3:
        return 0.0
    return len(overlap) / len(left_terms | right_terms)


def _parse_search_filters(query: str) -> tuple[str, dict[str, str]]:
    filters: dict[str, str] = {}
    cleaned: list[str] = []
    tokens = str(query).split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        lowered = token.lower()
        matched_key = None
        for key in ("category", "project", "tag", "shelf"):
            prefix = f"{key}:"
            if lowered.startswith(prefix):
                matched_key = key
                break
        if not matched_key:
            cleaned.append(token)
            index += 1
            continue

        raw_value = token.split(":", 1)[1]
        index += 1
        if (
            matched_key in {"category", "shelf"}
            and raw_value.lower() == "sql"
            and index < len(tokens)
            and tokens[index].lower() == "queries"
        ):
            raw_value += f" {tokens[index]}"
            index += 1
        value = raw_value.strip().strip("\"'")
        if value:
            normalized_key = "category" if matched_key == "shelf" else matched_key
            filters[normalized_key] = _normalize_tag(value) if normalized_key == "tag" else value
    return " ".join(cleaned).strip(), filters


def _redact_event_payload(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_event_payload(entry) for entry in value]
    if isinstance(value, tuple):
        return [_redact_event_payload(entry) for entry in value]
    if isinstance(value, dict):
        return {str(key): _redact_event_payload(entry) for key, entry in value.items()}
    return value


def _event_payload_for_report(payload_json: str) -> Any:
    try:
        return _redact_event_payload(json.loads(payload_json))
    except json.JSONDecodeError:
        return redact_text(payload_json)


def _event_hash(
    *,
    event_id: str,
    item_id: str | None,
    event_type: str,
    payload_json: str,
    elapsed_ms: float,
    created_at: str,
    previous_event_hash: str | None,
) -> str:
    material = {
        "id": event_id,
        "item_id": item_id,
        "event_type": event_type,
        "payload_json": payload_json,
        "elapsed_ms": float(elapsed_ms),
        "created_at": created_at,
        "previous_event_hash": previous_event_hash,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class SkratchedStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts_root = self.db_path.parent / "artifacts"
        self.artifacts_root.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                preview TEXT NOT NULL,
                summary TEXT NOT NULL,
                category TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                family_id TEXT NOT NULL,
                project TEXT,
                source TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                source TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                path TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS facets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                key TEXT NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS families (
                id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS links (
                id TEXT PRIMARY KEY,
                from_item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                to_item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                link_type TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS item_versions (
                id TEXT PRIMARY KEY,
                old_item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                new_item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                relation TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                item_id TEXT REFERENCES items(id) ON DELETE SET NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                elapsed_ms REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                previous_event_hash TEXT,
                event_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS summaries (
                id TEXT PRIMARY KEY,
                item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL,
                scope_type TEXT NOT NULL DEFAULT 'item',
                scope_value TEXT,
                item_count INTEGER NOT NULL DEFAULT 1,
                content_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS safe_exports (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                bundle_hash TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                media_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                artifact_hash TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shelves (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workspace_scans (
                id TEXT PRIMARY KEY,
                root TEXT NOT NULL,
                project TEXT,
                type_filter TEXT NOT NULL,
                filename TEXT,
                since TEXT,
                until_time TEXT,
                stale_before TEXT,
                max_depth INTEGER,
                refresh INTEGER NOT NULL DEFAULT 0,
                scanned_count INTEGER NOT NULL,
                candidate_count INTEGER NOT NULL,
                skipped_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workspace_candidates (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES workspace_scans(id) ON DELETE CASCADE,
                root TEXT NOT NULL,
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                project TEXT,
                type_label TEXT NOT NULL,
                media_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime TEXT NOT NULL,
                stat_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                captured_item_id TEXT REFERENCES items(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(root, path)
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS item_fts USING fts5(
                item_id UNINDEXED,
                content,
                preview,
                category,
                project,
                facets
            );
            """
        )
        self._ensure_event_integrity_columns()
        self._ensure_summary_rollup_columns()
        self._backfill_event_hashes()
        self.conn.commit()

    def _ensure_event_integrity_columns(self) -> None:
        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(events)").fetchall()}
        if "previous_event_hash" not in columns:
            self.conn.execute("ALTER TABLE events ADD COLUMN previous_event_hash TEXT")
        if "event_hash" not in columns:
            self.conn.execute("ALTER TABLE events ADD COLUMN event_hash TEXT")

    def _backfill_event_hashes(self) -> None:
        missing = self.conn.execute("SELECT count(*) AS n FROM events WHERE event_hash IS NULL").fetchone()["n"]
        if not missing:
            return
        previous_hash: str | None = None
        rows = self.conn.execute("SELECT rowid, * FROM events ORDER BY rowid").fetchall()
        for row in rows:
            event_hash = _event_hash(
                event_id=str(row["id"]),
                item_id=row["item_id"],
                event_type=str(row["event_type"]),
                payload_json=str(row["payload_json"]),
                elapsed_ms=float(row["elapsed_ms"]),
                created_at=str(row["created_at"]),
                previous_event_hash=previous_hash,
            )
            self.conn.execute(
                "UPDATE events SET previous_event_hash = ?, event_hash = ? WHERE rowid = ?",
                (previous_hash, event_hash, row["rowid"]),
            )
            previous_hash = event_hash

    def _ensure_summary_rollup_columns(self) -> None:
        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(summaries)").fetchall()}
        if "scope_type" not in columns:
            self.conn.execute("ALTER TABLE summaries ADD COLUMN scope_type TEXT NOT NULL DEFAULT 'item'")
        if "scope_value" not in columns:
            self.conn.execute("ALTER TABLE summaries ADD COLUMN scope_value TEXT")
        if "item_count" not in columns:
            self.conn.execute("ALTER TABLE summaries ADD COLUMN item_count INTEGER NOT NULL DEFAULT 1")
        if "content_hash" not in columns:
            self.conn.execute("ALTER TABLE summaries ADD COLUMN content_hash TEXT")

    def table_names(self) -> list[str]:
        rows = self.conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')").fetchall()
        return [row["name"] for row in rows]

    def count_rows(self, table: str) -> int:
        return int(self.conn.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"])

    def memory_summaries(
        self,
        *,
        recent_limit: int = 5,
        group_limit: int = 5,
    ) -> dict[str, Any]:
        anchor = self.conn.execute("SELECT id FROM items ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
        if not anchor:
            return {"summaries": []}

        def item_phrase(row: sqlite3.Row) -> str:
            project = f" [{row['project']}]" if row["project"] else ""
            return f"{row['category']}{project}: {row['summary']}"

        def rollup_hash(kind: str, scope_type: str, scope_value: str, item_count: int, summary: str) -> str:
            material = {
                "kind": kind,
                "scope_type": scope_type,
                "scope_value": scope_value,
                "item_count": item_count,
                "summary": summary,
            }
            encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
            return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

        rollups: list[dict[str, Any]] = []
        recent_rows = self.conn.execute(
            "SELECT * FROM items ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (max(1, min(int(recent_limit), 20)),),
        ).fetchall()
        if recent_rows:
            summary = "Recent captures: " + " | ".join(item_phrase(row) for row in recent_rows)
            rollups.append(
                {
                    "kind": "rollup:recent",
                    "scope_type": "recent",
                    "scope_value": "latest",
                    "item_count": len(recent_rows),
                    "summary": summary[:1000],
                }
            )

        project_rows = self.conn.execute(
            """
            SELECT project, count(*) AS item_count, max(created_at) AS latest_at
            FROM items
            WHERE project IS NOT NULL AND project != ''
            GROUP BY project
            ORDER BY item_count DESC, latest_at DESC, project
            LIMIT ?
            """,
            (max(1, min(int(group_limit), 20)),),
        ).fetchall()
        for project_row in project_rows:
            latest = self.conn.execute(
                "SELECT * FROM items WHERE project = ? ORDER BY created_at DESC, rowid DESC LIMIT 3",
                (project_row["project"],),
            ).fetchall()
            summary = f"Project {project_row['project']} has {project_row['item_count']} captures: "
            summary += " | ".join(item_phrase(row) for row in latest)
            rollups.append(
                {
                    "kind": "rollup:project",
                    "scope_type": "project",
                    "scope_value": str(project_row["project"]),
                    "item_count": int(project_row["item_count"]),
                    "summary": summary[:1000],
                }
            )

        category_rows = self.conn.execute(
            """
            SELECT category, count(*) AS item_count, max(created_at) AS latest_at
            FROM items
            GROUP BY category
            ORDER BY item_count DESC, latest_at DESC, category
            LIMIT ?
            """,
            (max(1, min(int(group_limit), 20)),),
        ).fetchall()
        for category_row in category_rows:
            latest = self.conn.execute(
                "SELECT * FROM items WHERE category = ? ORDER BY created_at DESC, rowid DESC LIMIT 3",
                (category_row["category"],),
            ).fetchall()
            summary = f"Category {category_row['category']} has {category_row['item_count']} captures: "
            summary += " | ".join(item_phrase(row) for row in latest)
            rollups.append(
                {
                    "kind": "rollup:category",
                    "scope_type": "category",
                    "scope_value": str(category_row["category"]),
                    "item_count": int(category_row["item_count"]),
                    "summary": summary[:1000],
                }
            )

        total_items = self.count_rows("items")
        category_counts = ", ".join(f"{row['category']}={row['item_count']}" for row in category_rows)
        latest_project = project_rows[0]["project"] if project_rows else "none"
        rollups.append(
            {
                "kind": "rollup:long_horizon",
                "scope_type": "long_horizon",
                "scope_value": "all",
                "item_count": total_items,
                "summary": f"Long-horizon memory contains {total_items} captures. Category mix: {category_counts or 'none'}. Most active project: {latest_project}.",
            }
        )

        now = utc_now_iso()
        self.conn.execute("DELETE FROM summaries WHERE kind LIKE 'rollup:%'")
        persisted: list[dict[str, Any]] = []
        for rollup in rollups:
            safe_summary = redact_text(str(rollup["summary"]))
            digest = rollup_hash(
                str(rollup["kind"]),
                str(rollup["scope_type"]),
                str(rollup["scope_value"]),
                int(rollup["item_count"]),
                safe_summary,
            )
            row = {
                "id": str(uuid.uuid4()),
                "item_id": anchor["id"],
                "kind": str(rollup["kind"]),
                "scope_type": str(rollup["scope_type"]),
                "scope_value": str(rollup["scope_value"]),
                "item_count": int(rollup["item_count"]),
                "summary": safe_summary,
                "content_hash": digest,
                "created_at": now,
            }
            self.conn.execute(
                """
                INSERT INTO summaries (
                    id, item_id, kind, summary, created_at,
                    scope_type, scope_value, item_count, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["item_id"],
                    row["kind"],
                    row["summary"],
                    row["created_at"],
                    row["scope_type"],
                    row["scope_value"],
                    row["item_count"],
                    row["content_hash"],
                ),
            )
            persisted.append(row)
        self.conn.commit()
        return {"summaries": persisted}

    def health_report(self) -> dict[str, Any]:
        counts = {
            "items": self.count_rows("items"),
            "artifacts": self.count_rows("artifacts"),
            "events": self.count_rows("events"),
        }
        tables = self.table_names()
        required_tables = {
            "items",
            "receipts",
            "facets",
            "families",
            "links",
            "events",
            "summaries",
            "safe_exports",
            "artifacts",
            "shelves",
            "workspace_scans",
            "workspace_candidates",
            "item_fts",
        }
        missing_tables = sorted(required_tables - set(tables))

        storage = {
            "ok": self.db_path.exists() and self.db_path.parent.exists(),
            "db_path": str(self.db_path),
            "parent": str(self.db_path.parent),
            "db_exists": self.db_path.exists(),
            "parent_exists": self.db_path.parent.exists(),
            "artifacts_root": str(self.artifacts_root),
            "artifacts_root_exists": self.artifacts_root.exists(),
        }

        fts_ok = True
        fts_error = None
        indexed_items = 0
        try:
            indexed_items = int(
                self.conn.execute("SELECT count(DISTINCT item_id) AS n FROM item_fts").fetchone()["n"]
            )
        except sqlite3.Error as exc:
            fts_ok = False
            fts_error = str(exc)

        search_ok = True
        search_error = None
        search_matches = 0
        try:
            search_matches = int(
                self.conn.execute(
                    "SELECT count(*) AS n FROM item_fts WHERE item_fts MATCH ?",
                    ("health",),
                ).fetchone()["n"]
            )
        except sqlite3.Error as exc:
            search_ok = False
            search_error = str(exc)

        redaction_checks = {
            "openrouter_key": "sk-or-v1-" + ("h" * 40) not in redact_text("OPENROUTER_API_KEY=sk-or-v1-" + ("h" * 40)),
            "database_url": "user:passw0rd" not in redact_text("DATABASE_URL=postgresql://user:passw0rd@localhost/db"),
            "bearer_token": "abcdefghijklmnopqrstuv" not in redact_text(
                "Authorization: Bearer abcdefghijklmnopqrstuv"
            ),
        }
        optional_ai_configured = any(
            os.environ.get(name)
            for name in (
                "OPENAI_API_KEY",
                "OPENROUTER_API_KEY",
                "ANTHROPIC_API_KEY",
            )
        )
        optional_ai = {
            "ok": True,
            "required": False,
            "configured": optional_ai_configured,
            "provider": "configured-env" if optional_ai_configured else None,
            "mode": "disabled-unless-configured",
        }
        event_integrity = self.event_integrity_report()

        report = {
            "ok": bool(
                storage["ok"]
                and not missing_tables
                and fts_ok
                and indexed_items == counts["items"]
                and search_ok
                and all(redaction_checks.values())
                and optional_ai["ok"]
                and event_integrity["ok"]
            ),
            "storage": storage,
            "storage_path": str(self.db_path),
            "tables": tables,
            "missing_tables": missing_tables,
            "counts": counts,
            "items": counts["items"],
            "artifacts": counts["artifacts"],
            "events": counts["events"],
            "indexes": {
                "fts": {
                    "ok": fts_ok and indexed_items == counts["items"],
                    "fresh": indexed_items == counts["items"],
                    "indexed_items": indexed_items,
                    "items": counts["items"],
                    "error": fts_error,
                }
            },
            "search": {
                "ok": search_ok,
                "probe": "health",
                "matches": search_matches,
                "error": search_error,
            },
            "redaction": {
                "ok": all(redaction_checks.values()),
                "checks": redaction_checks,
            },
            "optional_ai": optional_ai,
            "event_integrity": event_integrity,
        }
        return report

    def item_ids_by_content_hash(self, digest: str) -> list[str]:
        rows = self.conn.execute("SELECT id FROM items WHERE content_hash = ? ORDER BY created_at", (digest,)).fetchall()
        return [str(row["id"]) for row in rows]

    def _event(self, event_type: str, item_id: str | None, payload: dict[str, Any], elapsed_ms: float = 0) -> None:
        safe_payload = _redact_event_payload(payload)
        event_id = str(uuid.uuid4())
        created_at = utc_now_iso()
        payload_json = json.dumps(safe_payload, sort_keys=True)
        previous_row = self.conn.execute("SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1").fetchone()
        previous_event_hash = str(previous_row["event_hash"]) if previous_row and previous_row["event_hash"] else None
        event_hash = _event_hash(
            event_id=event_id,
            item_id=item_id,
            event_type=event_type,
            payload_json=payload_json,
            elapsed_ms=elapsed_ms,
            created_at=created_at,
            previous_event_hash=previous_event_hash,
        )
        self.conn.execute(
            """
            INSERT INTO events (
                id, item_id, event_type, payload_json, elapsed_ms, created_at,
                previous_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, item_id, event_type, payload_json, elapsed_ms, created_at, previous_event_hash, event_hash),
        )

    def _family_for_hash(self, digest: str, created_at: str) -> str:
        row = self.conn.execute("SELECT id FROM families WHERE content_hash = ?", (digest,)).fetchone()
        if row:
            return str(row["id"])
        family_id = f"fam_{digest[:16]}"
        self.conn.execute(
            "INSERT INTO families (id, content_hash, created_at) VALUES (?, ?, ?)",
            (family_id, digest, created_at),
        )
        return family_id

    def capture(
        self,
        text: str,
        *,
        source: str = "manual",
        project: str | None = None,
        path: str | None = None,
        created_at: str | None = None,
        filing_mode: str = "auto",
        ai_adapter: Callable[[str, dict[str, Any]], Any] | None = None,
        ai_provider: str = "optional",
    ) -> dict[str, Any]:
        started = time.perf_counter()
        analysis_started = time.perf_counter()
        created = created_at or utc_now_iso()
        analysis = analyze_capture(text, source=source, filename=path)
        analysis, ai_diagnostics = run_optional_ai_analysis(
            text,
            analysis,
            adapter=ai_adapter,
            provider=ai_provider,
        )
        analysis_ms = (time.perf_counter() - analysis_started) * 1000
        inferred_category = str(analysis["category"])
        filing_mode = filing_mode.strip().lower()
        if filing_mode not in {"auto", "suggest"}:
            raise ValueError("filing_mode must be auto or suggest")
        if filing_mode == "suggest":
            facets = dict(analysis.get("facets") or {})
            facets["filing_mode"] = "suggest"
            facets["suggested_category"] = inferred_category
            facets["filing_suggestion_status"] = "pending"
            facets["filing_suggestion_reason"] = f"pattern-based capture analysis matched {inferred_category}"
            facets["filing_suggestion_confidence"] = "high" if inferred_category != "notes" else "low"
            analysis["facets"] = facets
            analysis["category"] = "inbox"
        family_id = self._family_for_hash(analysis["content_hash"], created)
        item_id = str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO items (
                id, content, preview, summary, category, sensitivity, content_hash,
                family_id, project, source, analysis_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                text,
                analysis["preview"],
                analysis["summary"],
                analysis["category"],
                analysis["sensitivity"],
                analysis["content_hash"],
                family_id,
                project,
                source,
                json.dumps(analysis, sort_keys=True),
                created,
                created,
            ),
        )
        self.conn.execute(
            "INSERT INTO receipts (id, item_id, source, content_hash, path, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, source, analysis["content_hash"], path, created),
        )
        for key, value in analysis["facets"].items():
            values = value if isinstance(value, list) else [value]
            for facet_value in values:
                if facet_value is not None:
                    self.conn.execute(
                        "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                        (item_id, key, str(facet_value)),
                    )
        self.conn.execute(
            "INSERT INTO summaries (id, item_id, kind, summary, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, "capture", analysis["summary"], created),
        )
        index_started = time.perf_counter()
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (
                item_id,
                text,
                analysis["preview"],
                analysis["category"],
                project or "",
                json.dumps(analysis["facets"], sort_keys=True),
            ),
        )
        index_ms = (time.perf_counter() - index_started) * 1000
        self._event(
            "index.updated",
            item_id,
            {
                "lifecycle": "index",
                "index": "item_fts",
                "operation": "upsert",
                "item_id": item_id,
                "indexed_fields": ["content", "preview", "category", "project", "facets"],
                "timing": {"total_ms": round(index_ms, 3)},
            },
            index_ms,
        )
        self._maybe_record_near_duplicate(item_id, text, analysis, project)
        elapsed = (time.perf_counter() - started) * 1000
        self._event(
            "capture.created",
            item_id,
            {
                "lifecycle": "capture",
                "category": analysis["category"],
                "sensitivity": analysis["sensitivity"],
                "content_hash": analysis["content_hash"],
                "family_id": family_id,
                "filing_mode": filing_mode,
                "timing": {
                    "total_ms": round(elapsed, 3),
                    "analysis_ms": round(analysis_ms, 3),
                    "index_ms": round(index_ms, 3),
                },
            },
            elapsed,
        )
        if ai_diagnostics is not None:
            self._event("item.ai_analysis", item_id, ai_diagnostics)
        if filing_mode == "suggest":
            self._event(
                "item.filing_suggested",
                item_id,
                {
                    "target_category": inferred_category,
                    "current_category": "inbox",
                    "reason": analysis["facets"]["filing_suggestion_reason"],
                    "confidence": analysis["facets"]["filing_suggestion_confidence"],
                },
            )
        self.conn.commit()
        return self.get_item(item_id)

    def _maybe_record_near_duplicate(
        self,
        item_id: str,
        text: str,
        analysis: dict[str, Any],
        project: str | None,
    ) -> None:
        rows = self.conn.execute(
            """
            SELECT id, content, category, content_hash, created_at
            FROM items
            WHERE id != ? AND category = ?
            ORDER BY created_at DESC
            LIMIT 200
            """,
            (item_id, analysis["category"]),
        ).fetchall()
        best: tuple[float, sqlite3.Row] | None = None
        for row in rows:
            if row["content_hash"] == analysis["content_hash"]:
                continue
            score = _near_duplicate_score(text, row["content"])
            if score >= 0.72 and (best is None or score > best[0]):
                best = (score, row)
        if best is None:
            return

        score, row = best
        facets = dict(analysis.get("facets") or {})
        facets.update(
            {
                "near_duplicate_of": row["id"],
                "near_duplicate_score": f"{score:.3f}",
                "near_duplicate_method": "redacted_lexical_jaccard",
            }
        )
        analysis["facets"] = facets
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE items SET analysis_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(analysis, sort_keys=True), now, item_id),
        )
        for key in ("near_duplicate_of", "near_duplicate_score", "near_duplicate_method"):
            self.conn.execute(
                "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                (item_id, key, str(facets[key])),
            )
        self.conn.execute("DELETE FROM item_fts WHERE item_id = ?", (item_id,))
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (
                item_id,
                text,
                analysis["preview"],
                analysis["category"],
                project or "",
                json.dumps(facets, sort_keys=True),
            ),
        )
        self.conn.execute(
            "INSERT INTO links (id, from_item_id, to_item_id, link_type, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, row["id"], "near_duplicate", now),
        )
        self._event(
            "item.near_duplicate_detected",
            item_id,
            {
                "existing_item_id": row["id"],
                "score": round(score, 3),
                "method": "redacted_lexical_jaccard",
            },
        )

    def capture_artifact(
        self,
        *,
        filename: str,
        content: bytes,
        media_type: str = "application/octet-stream",
        source: str = "file",
        project: str | None = None,
        created_at: str | None = None,
        extra_facets: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not content:
            raise ValueError("artifact content is required")
        started = time.perf_counter()
        created = created_at or utc_now_iso()
        safe_name = Path(filename).name or "artifact"
        artifact_hash = hashlib.sha256(content).hexdigest()
        suffix = Path(safe_name).suffix.lower()
        if len(suffix) > 12 or "/" in suffix or "\\" in suffix:
            suffix = ""
        storage_rel = Path("artifacts") / f"{artifact_hash}{suffix}"
        storage_path = self.db_path.parent / storage_rel
        tmp_path = storage_path.with_suffix(storage_path.suffix + f".{uuid.uuid4().hex}.tmp")
        tmp_path.write_bytes(content)
        tmp_path.replace(storage_path)

        category = self._artifact_category(safe_name, media_type, source)
        tags = ["file", "artifact"]
        if category.startswith("screenshots"):
            tags.append("screenshot")
        metadata_text = "\n".join(
            [
                f"File: {safe_name}",
                f"Media type: {media_type}",
                f"Byte size: {len(content)}",
                f"Artifact hash: {artifact_hash}",
                f"Source: {source}",
            ]
        )
        preview = f"{category}: {safe_name} ({media_type}, {len(content)} bytes, hash {artifact_hash[:12]})"
        analysis = {
            "category": category,
            "sensitivity": "safe",
            "preview": preview,
            "summary": preview[:180],
            "content_hash": artifact_hash,
            "facets": {
                "source": source,
                "vendors": [],
                "tags": tags,
                "filename": safe_name,
                "media_type": media_type,
                "byte_size": len(content),
                "artifact_hash": artifact_hash,
                "artifact_path": storage_rel.as_posix(),
                "length": len(metadata_text),
                "chunk_count": 0,
            },
            "chunks": [],
        }
        if extra_facets:
            analysis["facets"].update(extra_facets)
        family_id = self._family_for_hash(artifact_hash, created)
        item_id = str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO items (
                id, content, preview, summary, category, sensitivity, content_hash,
                family_id, project, source, analysis_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                metadata_text,
                preview,
                preview[:180],
                category,
                "safe",
                artifact_hash,
                family_id,
                project,
                source,
                json.dumps(analysis, sort_keys=True),
                created,
                created,
            ),
        )
        self.conn.execute(
            "INSERT INTO receipts (id, item_id, source, content_hash, path, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, source, artifact_hash, storage_rel.as_posix(), created),
        )
        self.conn.execute(
            """
            INSERT INTO artifacts (id, item_id, filename, media_type, byte_size, artifact_hash, storage_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), item_id, safe_name, media_type, len(content), artifact_hash, storage_rel.as_posix(), created),
        )
        for key, value in analysis["facets"].items():
            values = value if isinstance(value, list) else [value]
            for facet_value in values:
                if facet_value is not None:
                    self.conn.execute(
                        "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                        (item_id, key, str(facet_value)),
                    )
        self.conn.execute(
            "INSERT INTO summaries (id, item_id, kind, summary, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, "artifact", preview[:180], created),
        )
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (
                item_id,
                metadata_text,
                preview,
                category,
                project or "",
                json.dumps(analysis["facets"], sort_keys=True),
            ),
        )
        elapsed = (time.perf_counter() - started) * 1000
        self._event(
            "capture.artifact_created",
            item_id,
            {
                "category": category,
                "content_hash": artifact_hash,
                "family_id": family_id,
                "filename": safe_name,
                "media_type": media_type,
                "byte_size": len(content),
                "storage_path": storage_rel.as_posix(),
            },
            elapsed,
        )
        self.conn.commit()
        return self.get_item(item_id)

    def scan_screenshot_watch(
        self,
        directory: str | Path,
        *,
        project: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        original = Path(directory).expanduser()
        if original.is_symlink():
            raise ValueError("screenshot directory cannot be a symlink")
        root = original.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("screenshot directory is not a directory")
        limit = max(1, min(int(limit), 25))
        candidates: list[tuple[int, Path]] = []
        for path in root.iterdir():
            if path.is_symlink() or not path.is_file():
                continue
            if not self._looks_like_screenshot(path):
                continue
            stat = path.stat()
            candidates.append((int(stat.st_mtime_ns), path))
        candidates.sort(reverse=True, key=lambda pair: pair[0])

        imported: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for _, path in candidates[:limit]:
            content = path.read_bytes()
            artifact_hash = hashlib.sha256(content).hexdigest()
            if self.conn.execute("SELECT 1 FROM artifacts WHERE artifact_hash = ? LIMIT 1", (artifact_hash,)).fetchone():
                skipped.append(
                    {
                        "filename": path.name,
                        "observed_path": str(path.resolve()),
                        "artifact_hash": artifact_hash,
                        "reason": "duplicate_artifact_hash",
                    }
                )
                continue
            stat = path.stat()
            stat_fingerprint = f"size={stat.st_size};mtime_ns={stat.st_mtime_ns};inode={getattr(stat, 'st_ino', 0)}"
            item = self.capture_artifact(
                filename=path.name,
                content=content,
                media_type=mimetypes.guess_type(str(path))[0] or "application/octet-stream",
                source="screenshot-watch",
                project=project,
                extra_facets={
                    "observed_path": str(path.resolve()),
                    "stat_fingerprint": stat_fingerprint,
                    "watch_directory": str(root),
                },
            )
            self._event(
                "capture.screenshot_watch_imported",
                item["id"],
                {
                    "filename": path.name,
                    "observed_path": str(path.resolve()),
                    "stat_fingerprint": stat_fingerprint,
                    "artifact_hash": artifact_hash,
                },
            )
            self.conn.commit()
            imported.append(item)
        return {
            "directory": str(root),
            "imported_count": len(imported),
            "skipped_count": len(skipped),
            "items": imported,
            "skipped": skipped,
        }

    def workspace_scan_preview(
        self,
        root: str | Path,
        *,
        project: str | None = None,
        type_filter: str | None = None,
        filename: str | None = None,
        since: str | None = None,
        until: str | None = None,
        stale: str | None = None,
        max_depth: int | None = None,
        refresh: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        original = Path(root).expanduser()
        if original.is_symlink():
            raise ValueError("workspace scout root cannot be a symlink")
        resolved_root = original.resolve(strict=True)
        if not resolved_root.is_dir():
            raise ValueError("workspace scout root is not a directory")
        if max_depth is not None:
            max_depth = max(0, min(int(max_depth), 25))
        limit = max(1, min(int(limit), 250))
        safe_type = str(type_filter or "all").strip() or "all"
        safe_filename = str(filename or "").strip() or None
        since_dt = _parse_workspace_time(since)
        until_dt = _parse_workspace_time(until)
        stale_dt = _parse_workspace_time(stale)
        previous_index_age_seconds = self._workspace_index_age_seconds(str(resolved_root))

        scan_id = str(uuid.uuid4())
        created = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO workspace_scans (
                id, root, project, type_filter, filename, since, until_time,
                stale_before, max_depth, refresh, scanned_count, candidate_count,
                skipped_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                str(resolved_root),
                project,
                safe_type,
                safe_filename,
                since,
                until,
                stale,
                max_depth,
                1 if refresh else 0,
                0,
                0,
                0,
                created,
            ),
        )
        if not refresh:
            cached_candidates = self._workspace_cached_candidates(
                str(resolved_root),
                type_filter=safe_type,
                filename=safe_filename,
                since_dt=since_dt,
                until_dt=until_dt,
                stale_dt=stale_dt,
                max_depth=max_depth,
                limit=limit,
            )
            if cached_candidates:
                self.conn.execute(
                    "UPDATE workspace_scans SET scanned_count = ?, candidate_count = ?, skipped_count = ? WHERE id = ?",
                    (0, len(cached_candidates), 0, scan_id),
                )
                elapsed = (time.perf_counter() - started) * 1000
                self._event(
                    "workspace_scout.scan_previewed",
                    None,
                    {
                        "scan_id": scan_id,
                        "root": str(resolved_root),
                        "project": project,
                        "type_filter": safe_type,
                        "candidate_count": len(cached_candidates),
                        "scanned_count": 0,
                        "metadata_only": True,
                        "cache_hit": True,
                        "timing": {"total_ms": round(elapsed, 3)},
                    },
                    elapsed,
                )
                self.conn.commit()
                return {
                    "schema": "skratched.workspace_scout.preview.v1",
                    "scan_id": scan_id,
                    "root": str(resolved_root),
                    "project": project,
                    "type_filter": safe_type,
                    "filename": safe_filename,
                    "since": since,
                    "until": until,
                    "stale": stale,
                    "max_depth": max_depth,
                    "metadata_only": True,
                    "cache_hit": True,
                    "index_age_seconds": previous_index_age_seconds,
                    "scanned_count": 0,
                    "candidate_count": len(cached_candidates),
                    "skipped_count": 0,
                    "candidates": cached_candidates,
                }
        candidates: list[dict[str, Any]] = []
        skipped_count = 0
        scanned_count = 0

        for current, dirnames, filenames in os.walk(resolved_root):
            current_path = Path(current)
            dirnames[:] = [
                name
                for name in dirnames
                if name not in WORKSPACE_SCOUT_SKIP_DIRS and not (current_path / name).is_symlink()
            ]
            rel_dir = current_path.relative_to(resolved_root)
            dir_depth = 0 if str(rel_dir) == "." else len(rel_dir.parts)
            if max_depth is not None and dir_depth >= max_depth:
                dirnames[:] = []
            for name in filenames:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    skipped_count += 1
                    continue
                rel = path.relative_to(resolved_root)
                depth = len(rel.parts)
                if max_depth is not None and depth > max_depth:
                    skipped_count += 1
                    continue
                scanned_count += 1
                if safe_filename and name != safe_filename:
                    continue
                if not _workspace_matches_type(path, safe_type):
                    continue
                stat = path.stat()
                mtime_dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if since_dt and mtime_dt < since_dt:
                    continue
                if until_dt and mtime_dt > until_dt:
                    continue
                if stale_dt and mtime_dt >= stale_dt:
                    continue
                type_label = _workspace_type_label(path)
                media_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
                path_resolved = path.resolve(strict=True)
                stat_fingerprint = f"size={stat.st_size};mtime_ns={stat.st_mtime_ns};inode={getattr(stat, 'st_ino', 0)}"
                candidate_id = f"wsc_{hashlib.sha256(str(path_resolved).encode('utf-8')).hexdigest()[:20]}"
                captured = self.conn.execute(
                    "SELECT item_id FROM receipts WHERE path = ? ORDER BY created_at DESC LIMIT 1",
                    (str(path_resolved),),
                ).fetchone()
                existing = self.conn.execute(
                    "SELECT captured_item_id FROM workspace_candidates WHERE root = ? AND path = ?",
                    (str(resolved_root), str(path_resolved)),
                ).fetchone()
                captured_item_id = (
                    str(captured["item_id"])
                    if captured and captured["item_id"]
                    else (str(existing["captured_item_id"]) if existing and existing["captured_item_id"] else None)
                )
                status = "captured" if captured_item_id else "candidate"
                self.conn.execute(
                    """
                    INSERT INTO workspace_candidates (
                        id, scan_id, root, path, name, relative_path, project, type_label,
                        media_type, size, mtime, stat_fingerprint, status, captured_item_id,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(root, path) DO UPDATE SET
                        scan_id = excluded.scan_id,
                        project = excluded.project,
                        type_label = excluded.type_label,
                        media_type = excluded.media_type,
                        size = excluded.size,
                        mtime = excluded.mtime,
                        stat_fingerprint = excluded.stat_fingerprint,
                        status = excluded.status,
                        captured_item_id = COALESCE(workspace_candidates.captured_item_id, excluded.captured_item_id),
                        updated_at = excluded.updated_at
                    """,
                    (
                        candidate_id,
                        scan_id,
                        str(resolved_root),
                        str(path_resolved),
                        name,
                        rel.as_posix(),
                        project,
                        type_label,
                        media_type,
                        int(stat.st_size),
                        _system_timestamp_to_iso(stat.st_mtime),
                        stat_fingerprint,
                        status,
                        captured_item_id,
                        created,
                        created,
                    ),
                )
                candidate = self._workspace_candidate_by_id(candidate_id)
                if candidate:
                    candidates.append(candidate)
                if len(candidates) >= limit:
                    break
            if len(candidates) >= limit:
                break

        self.conn.execute(
            "UPDATE workspace_scans SET scanned_count = ?, candidate_count = ?, skipped_count = ? WHERE id = ?",
            (scanned_count, len(candidates), skipped_count, scan_id),
        )
        elapsed = (time.perf_counter() - started) * 1000
        self._event(
            "workspace_scout.scan_previewed",
            None,
            {
                "scan_id": scan_id,
                "root": str(resolved_root),
                "project": project,
                "type_filter": safe_type,
                "candidate_count": len(candidates),
                "scanned_count": scanned_count,
                "metadata_only": True,
                "timing": {"total_ms": round(elapsed, 3)},
            },
            elapsed,
        )
        self.conn.commit()
        return {
            "schema": "skratched.workspace_scout.preview.v1",
            "scan_id": scan_id,
            "root": str(resolved_root),
            "project": project,
            "type_filter": safe_type,
            "filename": safe_filename,
            "since": since,
            "until": until,
            "stale": stale,
            "max_depth": max_depth,
            "metadata_only": True,
            "cache_hit": False,
            "index_age_seconds": self._workspace_index_age_seconds(str(resolved_root)),
            "scanned_count": scanned_count,
            "candidate_count": len(candidates),
            "skipped_count": skipped_count,
            "candidates": candidates,
        }

    def capture_workspace_candidate(
        self,
        candidate_id: str,
        *,
        project: str | None = None,
        import_content: bool = False,
        local_unlock: bool = False,
    ) -> dict[str, Any]:
        candidate = self._workspace_candidate_by_id(candidate_id)
        if not candidate:
            raise ValueError("workspace candidate not found")
        path = Path(str(candidate["path"]))
        if path.is_symlink():
            raise ValueError("workspace candidate path cannot be a symlink")
        if not path.is_file():
            raise ValueError("workspace candidate path is not a file")
        type_label = str(candidate["type_label"])
        chosen_project = project or candidate.get("project")
        if import_content and type_label == "secrets" and not local_unlock:
            raise PermissionError("local unlock is required before importing secret-like workspace content")

        facets = {
            "workspace_scout_candidate_id": candidate_id,
            "workspace_scout_scan_id": candidate["scan_id"],
            "workspace_scout_root": candidate["root"],
            "workspace_scout_path": candidate["path"],
            "workspace_scout_relative_path": candidate["relative_path"],
            "workspace_scout_type": type_label,
            "workspace_scout_mtime": candidate["mtime"],
            "stat_fingerprint": candidate["stat_fingerprint"],
        }
        if not import_content:
            text = "\n".join(
                [
                    f"Workspace Scout candidate: {candidate['relative_path']}",
                    f"Type: {type_label}",
                    f"Modified: {candidate['mtime']}",
                    f"Size: {candidate['size']} bytes",
                    "Mode: metadata only",
                ]
            )
            item = self.capture(
                text,
                source="workspace-scout",
                project=chosen_project,
                path=str(candidate["path"]),
            )
            item = self._force_item_category_and_facets(
                item["id"],
                "workspace-scout",
                {
                    **facets,
                    "workspace_scout_mode": "metadata_only",
                    "tags": ["workspace-scout", type_label],
                    "risk_class": "safe",
                    "risk_reasons": ["metadata-only workspace candidate"],
                },
            )
        elif type_label == "screenshots" or str(candidate["media_type"]).startswith("image/"):
            item = self.capture_artifact(
                filename=str(candidate["name"]),
                content=path.read_bytes(),
                media_type=str(candidate["media_type"]),
                source="workspace-scout",
                project=chosen_project,
                extra_facets={**facets, "workspace_scout_mode": "content_import"},
            )
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                item = self.capture_artifact(
                    filename=str(candidate["name"]),
                    content=path.read_bytes(),
                    media_type=str(candidate["media_type"]),
                    source="workspace-scout",
                    project=chosen_project,
                    extra_facets={**facets, "workspace_scout_mode": "content_import"},
                )
            else:
                item = self.capture(
                    text,
                    source="workspace-scout",
                    project=chosen_project,
                    path=str(candidate["path"]),
                )
                item = self._merge_item_facets(item["id"], {**facets, "workspace_scout_mode": "content_import"})

        self.conn.execute(
            """
            UPDATE workspace_candidates
            SET status = 'captured', captured_item_id = ?, updated_at = ?
            WHERE id = ?
            """,
            (item["id"], utc_now_iso(), candidate_id),
        )
        self._event(
            "workspace_scout.candidate_captured",
            item["id"],
            {
                "candidate_id": candidate_id,
                "mode": "content_import" if import_content else "metadata_only",
                "type_label": type_label,
                "path": str(candidate["path"]),
            },
        )
        self.conn.commit()
        return self.get_item(item["id"])

    def _workspace_candidate_by_id(self, candidate_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM workspace_candidates WHERE id = ?", (candidate_id,)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "scan_id": row["scan_id"],
            "root": row["root"],
            "path": row["path"],
            "name": row["name"],
            "relative_path": row["relative_path"],
            "project": row["project"],
            "type_label": row["type_label"],
            "media_type": row["media_type"],
            "size": int(row["size"]),
            "mtime": row["mtime"],
            "stat_fingerprint": row["stat_fingerprint"],
            "status": row["status"],
            "captured_item_id": row["captured_item_id"],
            "metadata_only": True,
            "preview": f"{row['type_label']}: {row['relative_path']} ({row['size']} bytes, modified {row['mtime']})",
        }

    def _workspace_index_age_seconds(self, root: str) -> int:
        row = self.conn.execute(
            "SELECT created_at FROM workspace_scans WHERE root = ? ORDER BY created_at DESC LIMIT 1",
            (root,),
        ).fetchone()
        if not row:
            return 0
        try:
            created = _parse_iso(str(row["created_at"]))
            return max(0, int((datetime.now(timezone.utc) - created).total_seconds()))
        except ValueError:
            return 0

    def _workspace_cached_candidates(
        self,
        root: str,
        *,
        type_filter: str,
        filename: str | None,
        since_dt: datetime | None,
        until_dt: datetime | None,
        stale_dt: datetime | None,
        max_depth: int | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id FROM workspace_candidates WHERE root = ? ORDER BY mtime DESC, relative_path LIMIT 1000",
            (root,),
        ).fetchall()
        candidates: list[dict[str, Any]] = []
        for row in rows:
            candidate = self._workspace_candidate_by_id(str(row["id"]))
            if not candidate:
                continue
            path = Path(str(candidate["path"]))
            if filename and candidate["name"] != filename:
                continue
            if type_filter and type_filter != "all" and not _workspace_matches_type(path, type_filter):
                continue
            if max_depth is not None and len(str(candidate["relative_path"]).split("/")) > max_depth:
                continue
            try:
                mtime_dt = _parse_iso(str(candidate["mtime"]))
            except ValueError:
                continue
            if since_dt and mtime_dt < since_dt:
                continue
            if until_dt and mtime_dt > until_dt:
                continue
            if stale_dt and mtime_dt >= stale_dt:
                continue
            candidates.append(candidate)
            if len(candidates) >= limit:
                break
        return candidates

    def _looks_like_screenshot(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        if suffix not in {".png", ".jpg", ".jpeg", ".webp", ".heic"}:
            return False
        name = path.name.lower()
        return "screenshot" in name or "screen shot" in name

    def _artifact_category(self, filename: str, media_type: str, source: str) -> str:
        haystack = f"{filename} {media_type} {source}".lower()
        if "product" in haystack:
            return "screenshots-products"
        if "screenshot" in haystack or media_type.lower().startswith("image/") or source.startswith("screenshot"):
            return "screenshots-work"
        return "files"

    def _merge_item_facets(self, item_id: str, facets: dict[str, Any]) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        analysis = json.loads(row["analysis_json"])
        merged = dict(analysis.get("facets") or {})
        merged.update(facets)
        analysis["facets"] = merged
        now = utc_now_iso()
        self.conn.execute("UPDATE items SET analysis_json = ?, updated_at = ? WHERE id = ?", (json.dumps(analysis, sort_keys=True), now, item_id))
        for key, value in facets.items():
            self.conn.execute("DELETE FROM facets WHERE item_id = ? AND key = ?", (item_id, key))
            values = value if isinstance(value, list) else [value]
            for facet_value in values:
                if facet_value is not None:
                    self.conn.execute(
                        "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                        (item_id, key, str(facet_value)),
                    )
        self.conn.execute("DELETE FROM item_fts WHERE item_id = ?", (item_id,))
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, row["content"], row["preview"], row["category"], row["project"] or "", json.dumps(merged, sort_keys=True)),
        )
        return self.get_item(item_id)

    def _force_item_category_and_facets(self, item_id: str, category: str, facets: dict[str, Any]) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        analysis = json.loads(row["analysis_json"])
        merged = dict(analysis.get("facets") or {})
        merged.update(facets)
        analysis["category"] = category
        analysis["facets"] = merged
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE items SET category = ?, analysis_json = ?, updated_at = ? WHERE id = ?",
            (category, json.dumps(analysis, sort_keys=True), now, item_id),
        )
        self.conn.execute("DELETE FROM facets WHERE item_id = ?", (item_id,))
        for key, value in merged.items():
            values = value if isinstance(value, list) else [value]
            for facet_value in values:
                if facet_value is not None:
                    self.conn.execute(
                        "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                        (item_id, key, str(facet_value)),
                    )
        self.conn.execute("DELETE FROM item_fts WHERE item_id = ?", (item_id,))
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, row["content"], row["preview"], category, row["project"] or "", json.dumps(merged, sort_keys=True)),
        )
        return self.get_item(item_id)

    def get_item(self, item_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        return self._row_to_item(row)

    def reveal_item(self, item_id: str, *, local_unlock: bool, reason: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        if row["sensitivity"] == "sensitive" and not local_unlock:
            self._event(
                "item.reveal_denied",
                item_id,
                {"reason": reason, "sensitivity": row["sensitivity"]},
            )
            self.conn.commit()
            raise PermissionError("local unlock required to reveal sensitive content")

        self._event(
            "item.revealed",
            item_id,
            {
                "reason": reason,
                "sensitivity": row["sensitivity"],
                "content_hash": row["content_hash"],
            },
        )
        self.conn.commit()
        item = self._row_to_item(row, include_content=False)
        item["content"] = row["content"]
        return item

    def events_for_item(self, item_id: str | None, *, event_type: str | None = None) -> list[dict[str, Any]]:
        if item_id is None and event_type:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE item_id IS NULL AND event_type = ? ORDER BY rowid",
                (event_type,),
            ).fetchall()
        elif event_type:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE item_id = ? AND event_type = ? ORDER BY rowid",
                (item_id, event_type),
            ).fetchall()
        elif item_id is None:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE item_id IS NULL ORDER BY rowid",
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE item_id = ? ORDER BY rowid",
                (item_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "item_id": row["item_id"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload_json"]),
                "elapsed_ms": row["elapsed_ms"],
                "created_at": row["created_at"],
                "previous_event_hash": row["previous_event_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def event_integrity_report(self) -> dict[str, Any]:
        rows = self.conn.execute("SELECT rowid, * FROM events ORDER BY rowid").fetchall()
        previous_hash: str | None = None
        for index, row in enumerate(rows, start=1):
            stored_previous = row["previous_event_hash"]
            if stored_previous != previous_hash:
                return {
                    "ok": False,
                    "events": len(rows),
                    "verified_events": index - 1,
                    "failure": "previous_event_hash_mismatch",
                    "broken_event_id": row["id"],
                    "expected_previous_event_hash": previous_hash,
                    "stored_previous_event_hash": stored_previous,
                    "head_hash": previous_hash,
                    "broken_event": {
                        "id": row["id"],
                        "item_id": row["item_id"],
                        "event_type": row["event_type"],
                        "payload": _event_payload_for_report(str(row["payload_json"])),
                    },
                }
            computed_hash = _event_hash(
                event_id=str(row["id"]),
                item_id=row["item_id"],
                event_type=str(row["event_type"]),
                payload_json=str(row["payload_json"]),
                elapsed_ms=float(row["elapsed_ms"]),
                created_at=str(row["created_at"]),
                previous_event_hash=previous_hash,
            )
            if row["event_hash"] != computed_hash:
                return {
                    "ok": False,
                    "events": len(rows),
                    "verified_events": index - 1,
                    "failure": "event_hash_mismatch",
                    "broken_event_id": row["id"],
                    "stored_event_hash": row["event_hash"],
                    "computed_event_hash": computed_hash,
                    "head_hash": previous_hash,
                    "broken_event": {
                        "id": row["id"],
                        "item_id": row["item_id"],
                        "event_type": row["event_type"],
                        "payload": _event_payload_for_report(str(row["payload_json"])),
                    },
                }
            previous_hash = computed_hash
        return {
            "ok": True,
            "events": len(rows),
            "verified_events": len(rows),
            "failure": None,
            "broken_event_id": None,
            "head_hash": previous_hash,
        }

    def list_items(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM items ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_item(row) for row in rows]

    def categories(self) -> list[dict[str, Any]]:
        item_rows = self.conn.execute(
            "SELECT category, count(*) AS count FROM items GROUP BY category ORDER BY count DESC, category"
        ).fetchall()
        counts = {str(row["category"]): int(row["count"]) for row in item_rows}
        shelf_rows = self.conn.execute("SELECT category FROM shelves ORDER BY category").fetchall()
        for row in shelf_rows:
            counts.setdefault(str(row["category"]), 0)
        return [
            {"category": category, "count": count}
            for category, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
        ]

    def tags(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT value AS tag, count(DISTINCT item_id) AS count
            FROM facets
            WHERE key = ?
            GROUP BY value
            ORDER BY count DESC, value
            """,
            ("tags",),
        ).fetchall()
        return [{"tag": str(row["tag"]), "count": int(row["count"])} for row in rows]

    def update_tags(self, item_id: str, tags: list[str], *, reason: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        normalized: list[str] = []
        seen: set[str] = set()
        for value in tags:
            tag = _normalize_tag(value)
            if tag and tag not in seen:
                seen.add(tag)
                normalized.append(tag)
        analysis = json.loads(row["analysis_json"])
        facets = dict(analysis.get("facets") or {})
        previous = facets.get("tags") or []
        if not isinstance(previous, list):
            previous = [str(previous)]
        facets["tags"] = normalized
        analysis["facets"] = facets
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE items SET analysis_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(analysis, sort_keys=True), now, item_id),
        )
        self.conn.execute("DELETE FROM facets WHERE item_id = ? AND key = ?", (item_id, "tags"))
        for tag in normalized:
            self.conn.execute(
                "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                (item_id, "tags", tag),
            )
        self.conn.execute("DELETE FROM item_fts WHERE item_id = ?", (item_id,))
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (
                item_id,
                row["content"],
                row["preview"],
                row["category"],
                row["project"] or "",
                json.dumps(facets, sort_keys=True),
            ),
        )
        self._event(
            "item.tags_updated",
            item_id,
            {
                "previous_tags": [_normalize_tag(value) for value in previous if _normalize_tag(value)],
                "tags": normalized,
                "reason": reason,
            },
        )
        self.conn.commit()
        return self.get_item(item_id)

    def ensure_shelf(self, category: str, *, reason: str = "manual shelf") -> dict[str, Any]:
        category = category.strip()
        if not category:
            raise ValueError("category is required")
        created = utc_now_iso()
        shelf_id = f"shelf_{uuid.uuid5(uuid.NAMESPACE_URL, category).hex[:16]}"
        cursor = self.conn.execute(
            """
            INSERT OR IGNORE INTO shelves (id, category, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (shelf_id, category, reason, created),
        )
        inserted = cursor.rowcount == 1
        row = self.conn.execute("SELECT * FROM shelves WHERE category = ?", (category,)).fetchone()
        if not row:
            raise RuntimeError("shelf insert failed")
        if inserted:
            self._event("shelf.created", None, {"category": category, "reason": reason})
        self.conn.commit()
        return {"id": row["id"], "category": row["category"], "reason": row["reason"], "created_at": row["created_at"]}

    def refile_item(self, item_id: str, category: str, *, reason: str) -> dict[str, Any]:
        category = category.strip()
        if not category:
            raise ValueError("category is required")
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        previous = str(row["category"])
        if previous == category:
            return self.get_item(item_id)
        self.ensure_shelf(category, reason=reason)
        self._set_item_category(
            row,
            category,
            manual_filing=True,
            event_type="item.refiled",
            payload={
                "previous_category": previous,
                "new_category": category,
                "reason": reason,
            },
        )
        self.conn.commit()
        return self.get_item(item_id)

    def accept_filing_suggestion(self, item_id: str, *, reason: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        analysis = json.loads(row["analysis_json"])
        facets = dict(analysis.get("facets") or {})
        target = str(facets.get("suggested_category") or "").strip()
        status = str(facets.get("filing_suggestion_status") or "")
        if not target:
            raise ValueError("no filing suggestion available")
        if status == "accepted" and str(row["category"]) == target:
            return self.get_item(item_id)
        previous = str(row["category"])
        self.ensure_shelf(target, reason=reason)
        self._set_item_category(
            row,
            target,
            manual_filing=True,
            event_type="item.refiled",
            payload={
                "previous_category": previous,
                "new_category": target,
                "reason": reason,
                "source": "filing_suggestion",
            },
            facet_updates={
                "filing_suggestion_status": "accepted",
                "filing_suggestion_accepted_reason": reason,
            },
        )
        self._event(
            "item.filing_suggestion_accepted",
            item_id,
            {
                "previous_category": previous,
                "new_category": target,
                "reason": reason,
            },
        )
        self.conn.commit()
        return self.get_item(item_id)

    def undo_last_filing(self, item_id: str, *, reason: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise KeyError(item_id)
        events = self.conn.execute(
            """
            SELECT * FROM events
            WHERE item_id = ? AND event_type = ?
            ORDER BY created_at DESC
            """,
            (item_id, "item.refiled"),
        ).fetchall()
        current_category = str(row["category"])
        selected: dict[str, Any] | None = None
        for event in events:
            payload = json.loads(event["payload_json"])
            if payload.get("new_category") == current_category:
                selected = payload
                break
        if not selected:
            raise ValueError("no manual filing change to undo")
        restored = str(selected["previous_category"])
        self._set_item_category(
            row,
            restored,
            manual_filing=False,
            event_type="item.filing_undone",
            payload={
                "previous_category": current_category,
                "restored_category": restored,
                "reason": reason,
            },
        )
        self.conn.commit()
        return self.get_item(item_id)

    def _set_item_category(
        self,
        row: sqlite3.Row,
        category: str,
        *,
        manual_filing: bool,
        event_type: str,
        payload: dict[str, Any],
        facet_updates: dict[str, Any] | None = None,
    ) -> None:
        analysis = json.loads(row["analysis_json"])
        facets = dict(analysis.get("facets") or {})
        previous = str(row["category"])
        analysis["category"] = category
        facets.pop("manual_previous_category", None)
        if manual_filing:
            facets["manual_filing"] = True
            facets["manual_previous_category"] = previous
        else:
            facets.pop("manual_filing", None)
        if facet_updates:
            facets.update(facet_updates)
        analysis["facets"] = facets
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE items SET category = ?, analysis_json = ?, updated_at = ? WHERE id = ?",
            (category, json.dumps(analysis, sort_keys=True), now, row["id"]),
        )
        delete_keys = ["manual_filing", "manual_previous_category"]
        if facet_updates:
            delete_keys.extend(facet_updates.keys())
        placeholders = ", ".join("?" for _ in delete_keys)
        self.conn.execute(
            f"DELETE FROM facets WHERE item_id = ? AND key IN ({placeholders})",
            (row["id"], *delete_keys),
        )
        if manual_filing:
            self.conn.execute(
                "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                (row["id"], "manual_filing", "true"),
            )
            self.conn.execute(
                "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                (row["id"], "manual_previous_category", previous),
            )
        if facet_updates:
            for key, value in facet_updates.items():
                if value is not None:
                    self.conn.execute(
                        "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                        (row["id"], key, str(value)),
                    )
        self.conn.execute("DELETE FROM item_fts WHERE item_id = ?", (row["id"],))
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (
                row["id"],
                row["content"],
                row["preview"],
                category,
                row["project"] or "",
                json.dumps(facets, sort_keys=True),
            ),
        )
        self._event(event_type, row["id"], payload)

    def link_items(self, from_item_id: str, to_item_id: str, link_type: str) -> None:
        self.conn.execute(
            "INSERT INTO links (id, from_item_id, to_item_id, link_type, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), from_item_id, to_item_id, link_type, utc_now_iso()),
        )
        self._event("link.created", from_item_id, {"to_item_id": to_item_id, "link_type": link_type})
        self.conn.commit()

    def _action_card(self, item: dict[str, Any], *, action: str, status: str) -> dict[str, Any]:
        action = str(action or "reuse").strip().lower()
        if action not in {"reuse", "copy", "reference"}:
            raise ValueError("action must be one of reuse, copy, or reference")
        risk_class = str(item.get("risk_class") or "safe")
        risk_reasons = [str(reason) for reason in (item.get("risk_reasons") or [])]
        requires_approval = risk_class in {"caution", "sensitive", "blocked"} or item.get("sensitivity") == "sensitive"
        apply_allowed = risk_class != "blocked"
        material = {
            "item_id": item["id"],
            "content_hash": item.get("content_hash"),
            "action": action,
            "risk_class": risk_class,
        }
        action_id = f"action_{hashlib.sha256(json.dumps(material, sort_keys=True).encode('utf-8')).hexdigest()[:16]}"
        if risk_class == "blocked":
            decision = "blocked"
        elif requires_approval:
            decision = "approval_required"
        else:
            decision = "allowed"
        return {
            "schema": "skratched.action_card.v1",
            "action_id": action_id,
            "item_id": item["id"],
            "action": action,
            "status": status,
            "decision": decision,
            "category": item.get("category"),
            "sensitivity": item.get("sensitivity"),
            "risk_class": risk_class,
            "risk_reasons": risk_reasons,
            "requires_approval": requires_approval,
            "apply_allowed": apply_allowed,
            "preview": item.get("preview") or item.get("summary") or "",
            "checks": [
                {
                    "name": "local_only",
                    "ok": True,
                    "detail": "no cloud call or external execution",
                },
                {
                    "name": "content_execution",
                    "ok": True,
                    "detail": "Skratched records approval only and does not execute item content",
                },
                {
                    "name": "risk_class",
                    "ok": apply_allowed,
                    "detail": "; ".join(risk_reasons) or risk_class,
                },
            ],
            "reversible": True,
            "reversal_note": "Approval is audit-only; create a replacement or edited successor to supersede reuse guidance.",
        }

    def propose_item_action(self, item_id: str, *, action: str = "reuse") -> dict[str, Any]:
        item = self.get_item(item_id)
        card = self._action_card(item, action=action, status="proposed")
        self._event(
            "action.proposed",
            item_id,
            {
                "action_id": card["action_id"],
                "action": card["action"],
                "risk_class": card["risk_class"],
                "decision": card["decision"],
            },
        )
        self.conn.commit()
        return card

    def check_item_action(self, item_id: str, *, action: str = "reuse") -> dict[str, Any]:
        item = self.get_item(item_id)
        card = self._action_card(item, action=action, status="checked")
        self._event(
            "action.checked",
            item_id,
            {
                "action_id": card["action_id"],
                "action": card["action"],
                "risk_class": card["risk_class"],
                "decision": card["decision"],
                "checks": card["checks"],
            },
        )
        self.conn.commit()
        return card

    def apply_item_action(
        self,
        item_id: str,
        *,
        action: str = "reuse",
        approved: bool = False,
        reason: str = "apply action",
    ) -> dict[str, Any]:
        item = self.get_item(item_id)
        card = self._action_card(item, action=action, status="applied")
        if not card["apply_allowed"]:
            raise PermissionError("blocked action cannot be applied")
        if card["requires_approval"] and not approved:
            raise PermissionError("approval required before applying action")
        card["decision"] = "approved" if approved or card["requires_approval"] else "allowed"
        card["approved"] = bool(approved)
        safe_reason = redact_text(str(reason or "apply action"))
        self._event(
            "action.applied",
            item_id,
            {
                "action_id": card["action_id"],
                "action": card["action"],
                "risk_class": card["risk_class"],
                "decision": card["decision"],
                "approved": card["approved"],
                "reason": safe_reason,
            },
        )
        self.conn.commit()
        return card

    def mark_replacement(self, old_item_id: str, new_item_id: str, *, reason: str) -> None:
        self.get_item(old_item_id)
        self.get_item(new_item_id)
        self.conn.execute(
            """
            INSERT INTO item_versions (id, old_item_id, new_item_id, relation, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), old_item_id, new_item_id, "replaced_by", reason, utc_now_iso()),
        )
        self.conn.execute(
            "INSERT INTO links (id, from_item_id, to_item_id, link_type, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), old_item_id, new_item_id, "replaced_by", utc_now_iso()),
        )
        self._event(
            "item.deprecated",
            old_item_id,
            {"successor_id": new_item_id, "reason": reason},
        )
        self.conn.commit()

    def edit_item(self, item_id: str, new_text: str, *, reason: str = "edit") -> dict[str, Any]:
        old_item = self.get_item(item_id)
        text = str(new_text or "")
        if not text.strip():
            raise ValueError("text is required")
        new_item = self.capture(
            text,
            source="edit",
            project=old_item.get("project") or None,
        )
        created_at = utc_now_iso()
        safe_reason = redact_text(str(reason or "edit"))
        self.conn.execute(
            """
            INSERT INTO item_versions (id, old_item_id, new_item_id, relation, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), item_id, new_item["id"], "edited_to", safe_reason, created_at),
        )
        self.conn.execute(
            "INSERT INTO links (id, from_item_id, to_item_id, link_type, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, new_item["id"], "edited_to", created_at),
        )
        self._event(
            "item.edited",
            item_id,
            {"successor_id": new_item["id"], "relation": "edited_to", "reason": safe_reason},
        )
        self.conn.commit()
        return self.get_item(new_item["id"])

    def replacement_for_item(self, item_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            """
            SELECT old_item_id, new_item_id, relation, reason, created_at FROM item_versions
            WHERE old_item_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (item_id,),
        ).fetchone()
        if not row:
            return None
        successor = self.get_item(row["new_item_id"])
        return {
            "old_item_id": row["old_item_id"],
            "new_item_id": row["new_item_id"],
            "relation": row["relation"],
            "reason": row["reason"],
            "created_at": row["created_at"],
            "successor": successor,
        }

    def list_replacements(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT old_item_id, new_item_id, relation, reason, created_at FROM item_versions
            WHERE relation = 'replaced_by'
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "old": self.get_item(row["old_item_id"]),
                "new": self.get_item(row["new_item_id"]),
                "relation": row["relation"],
                "reason": row["reason"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def version_history(self, item_id: str) -> dict[str, Any]:
        self.get_item(item_id)
        edges_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
        ordered_ids: list[str] = []

        def add_item(candidate_id: str) -> None:
            if candidate_id not in ordered_ids:
                ordered_ids.append(candidate_id)

        current_id = item_id
        ancestors: list[sqlite3.Row] = []
        while True:
            row = self.conn.execute(
                """
                SELECT old_item_id, new_item_id, relation, reason, created_at FROM item_versions
                WHERE new_item_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (current_id,),
            ).fetchone()
            if not row:
                break
            ancestors.insert(0, row)
            current_id = str(row["old_item_id"])

        root_item_id = current_id
        add_item(root_item_id)
        linear_edges: list[sqlite3.Row] = []
        for row in ancestors:
            linear_edges.append(row)
            add_item(str(row["new_item_id"]))

        current_id = item_id
        if ancestors:
            current_id = str(ancestors[-1]["new_item_id"])
        while True:
            rows = self.conn.execute(
                """
                SELECT old_item_id, new_item_id, relation, reason, created_at FROM item_versions
                WHERE old_item_id = ?
                ORDER BY created_at ASC
                """,
                (current_id,),
            ).fetchall()
            if not rows:
                break
            row = rows[-1]
            linear_edges.append(row)
            add_item(str(row["new_item_id"]))
            current_id = str(row["new_item_id"])

        edges: list[dict[str, Any]] = []
        for row in linear_edges:
            key = (str(row["old_item_id"]), str(row["new_item_id"]), str(row["relation"]))
            if key in edges_by_key:
                continue
            edge = {
                "old_item_id": key[0],
                "new_item_id": key[1],
                "relation": key[2],
                "reason": str(row["reason"]),
                "created_at": str(row["created_at"]),
            }
            edges_by_key[key] = edge
            edges.append(edge)

        latest_item_id = ordered_ids[-1] if ordered_ids else item_id
        return {
            "schema": "skratched.version_history.v1",
            "root_item_id": root_item_id,
            "latest_item_id": latest_item_id,
            "items": [self.get_item(version_item_id) for version_item_id in ordered_ids],
            "edges": edges,
        }

    def context_graph(self, item_id: str, *, max_depth: int = 2) -> dict[str, Any]:
        max_depth = max(1, min(int(max_depth), 3))
        root = self.get_item(item_id)
        root["graph_depth"] = 0
        nodes: dict[str, dict[str, Any]] = {root["id"]: root}
        edges: list[dict[str, Any]] = []
        seen_edges: set[tuple[str, str, str]] = set()
        node_depths: dict[str, int] = {root["id"]: 0}

        def add_node(node_id: str, depth: int) -> None:
            if node_id not in nodes:
                nodes[node_id] = self.get_item(node_id)
            previous_depth = node_depths.get(node_id)
            if previous_depth is None or depth < previous_depth:
                node_depths[node_id] = depth
                nodes[node_id]["graph_depth"] = depth

        def add_edge(edge: dict[str, Any]) -> None:
            key = (str(edge["from"]), str(edge["to"]), str(edge["type"]))
            if key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(edge)

        queue: list[str] = [item_id]
        expanded: set[str] = set()
        while queue:
            current_id = queue.pop(0)
            if current_id in expanded:
                continue
            expanded.add(current_id)
            current_depth = node_depths[current_id]
            if current_depth >= max_depth:
                continue
            link_rows = self.conn.execute(
                """
                SELECT from_item_id, to_item_id, link_type, created_at FROM links
                WHERE from_item_id = ? OR to_item_id = ?
                ORDER BY created_at
                """,
                (current_id, current_id),
            ).fetchall()
            for row in link_rows:
                other_id = row["to_item_id"] if row["from_item_id"] == current_id else row["from_item_id"]
                next_depth = current_depth + 1
                add_node(row["from_item_id"], current_depth if row["from_item_id"] == current_id else next_depth)
                add_node(row["to_item_id"], current_depth if row["to_item_id"] == current_id else next_depth)
                add_edge(
                    {
                        "from": row["from_item_id"],
                        "to": row["to_item_id"],
                        "type": row["link_type"],
                        "created_at": row["created_at"],
                        "depth": next_depth,
                    }
                )
                if next_depth < max_depth and other_id not in expanded:
                    queue.append(other_id)

        for neighbor_row, edge_type in self._neighbor_capture_rows(item_id):
            neighbor_id = str(neighbor_row["id"])
            add_node(neighbor_id, 1)
            add_edge(
                {
                    "from": item_id,
                    "to": neighbor_id,
                    "type": edge_type,
                    "created_at": neighbor_row["created_at"],
                    "depth": 1,
                }
            )

        family_rows = self.conn.execute(
            "SELECT id FROM items WHERE family_id = ? AND id != ? ORDER BY created_at",
            (root["family_id"], item_id),
        ).fetchall()
        for row in family_rows:
            peer_id = row["id"]
            add_node(peer_id, 1)
            add_edge(
                {
                    "from": item_id,
                    "to": peer_id,
                    "type": "same_content_family",
                    "created_at": root["created_at"],
                    "depth": 1,
                }
            )

        replacement = self.conn.execute(
            """
            SELECT old_item_id, new_item_id, relation, reason, created_at FROM item_versions
            WHERE old_item_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (item_id,),
        ).fetchone()
        if replacement:
            add_node(replacement["new_item_id"], 1)
            root["deprecated"] = True
            root["successor_id"] = replacement["new_item_id"]
            root["successor_relation"] = replacement["relation"]
            root["replacement_reason"] = replacement["reason"]
            add_edge(
                {
                    "from": replacement["old_item_id"],
                    "to": replacement["new_item_id"],
                    "type": replacement["relation"],
                    "reason": replacement["reason"],
                    "created_at": replacement["created_at"],
                    "depth": 1,
                }
            )
        else:
            root["deprecated"] = False
            root["successor_id"] = None
            root["successor_relation"] = None

        summary, clusters, memory_hints = self._graph_memory_map(root, nodes, edges)
        return {
            "root": root,
            "nodes": list(nodes.values()),
            "edges": edges,
            "summary": summary,
            "clusters": clusters,
            "memory_hints": memory_hints,
        }

    def _graph_memory_map(
        self,
        root: dict[str, Any],
        nodes: dict[str, dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
        edge_types: dict[str, int] = {}
        categories: dict[str, int] = {}
        for node in nodes.values():
            category = str(node.get("category") or "uncategorized")
            categories[category] = categories.get(category, 0) + 1
        for edge in edges:
            edge_type = str(edge["type"])
            edge_types[edge_type] = edge_types.get(edge_type, 0) + 1

        linked_context: list[str] = []
        chronological_neighbors: list[str] = []
        duplicates: list[str] = []
        near_duplicates: list[str] = []
        replacement_path: list[str] = []
        root_id = str(root["id"])
        for edge in edges:
            edge_type = str(edge["type"])
            for endpoint in (str(edge["from"]), str(edge["to"])):
                if endpoint == root_id:
                    continue
                if edge_type == "same_content_family":
                    duplicates.append(endpoint)
                elif edge_type == "near_duplicate":
                    near_duplicates.append(endpoint)
                elif edge_type == "replaced_by":
                    replacement_path.append(endpoint)
                elif edge_type in {"previous_capture", "next_capture"}:
                    chronological_neighbors.append(endpoint)
                else:
                    linked_context.append(endpoint)

        def unique_ids(values: list[str]) -> list[str]:
            seen: set[str] = set()
            output: list[str] = []
            for value in values:
                if value not in seen:
                    seen.add(value)
                    output.append(value)
            return output

        linked_context = unique_ids(linked_context)
        chronological_neighbors = unique_ids(chronological_neighbors)
        duplicates = unique_ids(duplicates)
        near_duplicates = unique_ids(near_duplicates)
        replacement_path = unique_ids(replacement_path)
        clusters: list[dict[str, Any]] = []
        for name, item_ids in (
            ("linked context", linked_context),
            ("chronological neighbors", chronological_neighbors),
            ("duplicates", duplicates),
            ("near duplicates", near_duplicates),
            ("replacement path", replacement_path),
        ):
            if item_ids:
                clusters.append(
                    {
                        "name": name,
                        "count": len(item_ids),
                        "item_ids": item_ids,
                        "items": [nodes[item_id] for item_id in item_ids if item_id in nodes],
                    }
                )

        hints: list[str] = []
        if linked_context:
            hints.append(f"{len(linked_context)} linked context item{'s' if len(linked_context) != 1 else ''} nearby")
        if any(int(node.get("graph_depth") or 0) >= 2 for node in nodes.values()):
            hints.append("2-hop context trail available")
        if duplicates:
            hints.append(f"{len(duplicates)} duplicate-family peer{'s' if len(duplicates) != 1 else ''} tracked")
        if near_duplicates:
            hints.append(f"{len(near_duplicates)} near-duplicate revision{'s' if len(near_duplicates) != 1 else ''} nearby")
        if replacement_path:
            hints.append("replacement path available")
        if not hints:
            hints.append("no linked context yet")

        summary = {
            "root_id": root_id,
            "root_category": root["category"],
            "node_count": len(nodes),
            "edge_count": len(edges),
            "edge_types": dict(sorted(edge_types.items())),
            "categories": dict(sorted(categories.items())),
            "cluster_count": len(clusters),
        }
        return summary, clusters, hints

    def search(self, query: str, *, now: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        started = time.perf_counter()
        search_query, filters = _parse_search_filters(query)
        scoring_query = search_query or query
        lowered = scoring_query.lower()
        terms = [t for t in re_tokenize(lowered) if len(t) > 2 and t not in {"last", "find", "added", "the"}]
        fts_started = time.perf_counter()
        fts_scores, fts_diagnostics = self._fts_scores(terms)
        fts_ms = (time.perf_counter() - fts_started) * 1000
        wants_api_key = "api key" in lowered or "api keys" in lowered or "openrouter" in lowered
        secret_intent = wants_api_key or bool(
            {"credential", "credentials", "key", "keys", "secret", "secrets", "token", "tokens"} & set(terms)
        )
        sql_intent = bool({"sql", "query", "queries", "database", "table", "users"} & set(terms))
        cutoff = _query_cutoff(lowered, now=now)

        rows = self.conn.execute("SELECT * FROM items ORDER BY created_at DESC").fetchall()
        scored: list[tuple[float, dict[str, Any]]] = []
        scoring_started = time.perf_counter()
        for row in rows:
            item = self._row_to_item(row)
            created = _parse_iso(item["created_at"])
            if cutoff and created < cutoff:
                continue
            if not self._matches_search_filters(item, filters):
                continue
            haystack = " ".join(
                [
                    row["content"],
                    item["preview"],
                    item["category"],
                    item.get("project") or "",
                    json.dumps(item["facets"], sort_keys=True),
                ]
            ).lower()
            exact_score = 0.0
            for term in terms:
                if term in haystack:
                    exact_score += 1.0
            metadata_score = 0.0
            if secret_intent and item["category"] == "API-Keys":
                metadata_score += 4.0
            if wants_api_key and item["category"] == "API-Keys":
                metadata_score += 3.0
            if "openrouter" in lowered and "openrouter" in haystack:
                metadata_score += 3.0
            if sql_intent and item["category"] == "SQL queries":
                metadata_score += 4.0
            semantic = local_semantic_signal(scoring_query, haystack, category=item["category"], facets=item["facets"])
            semantic_score = float(semantic["score"])
            fts_score = float(fts_scores.get(item["id"], 0.0))
            total_score = exact_score + metadata_score + semantic_score + fts_score
            if total_score > 0 or (filters and not terms):
                item["associated"] = self.associated_items(item["id"])
                item["scores"] = {
                    "exact": round(exact_score, 3),
                    "fts": round(fts_score, 3),
                    "metadata": round(metadata_score, 3),
                    "semantic": round(semantic_score, 3),
                    "total": round(total_score, 3),
                }
                item["filters"] = dict(filters)
                item["semantic"] = semantic
                item["why"] = self._why(item, scoring_query, item["scores"], filters=filters)
                scored.append((total_score, item))

        scored.sort(key=lambda pair: (pair[0], pair[1]["created_at"]), reverse=True)
        scoring_ms = (time.perf_counter() - scoring_started) * 1000
        elapsed = (time.perf_counter() - started) * 1000
        self._event(
            "search.executed",
            None,
            {
                "lifecycle": "search",
                "query": query,
                "scoring_query": scoring_query,
                "filters": filters,
                "fts": fts_diagnostics,
                "results": len(scored[:limit]),
                "timing": {
                    "total_ms": round(elapsed, 3),
                    "fts_ms": round(fts_ms, 3),
                    "scoring_ms": round(scoring_ms, 3),
                },
            },
            elapsed,
        )
        self.conn.commit()
        return [item for _, item in scored[:limit]]

    def _fts_scores(self, terms: list[str]) -> tuple[dict[str, float], dict[str, Any]]:
        match_query = _fts_match_query(terms)
        diagnostics: dict[str, Any] = {
            "enabled": bool(match_query),
            "query": match_query,
            "matches": 0,
            "error": None,
        }
        if not match_query:
            return {}, diagnostics
        try:
            rows = self.conn.execute(
                """
                SELECT item_id, bm25(item_fts, 2.0, 4.0, 3.0, 2.0, 1.5) AS rank
                FROM item_fts
                WHERE item_fts MATCH ?
                ORDER BY rank
                LIMIT 100
                """,
                (match_query,),
            ).fetchall()
        except sqlite3.Error as exc:
            diagnostics["error"] = redact_text(str(exc))
            return {}, diagnostics
        diagnostics["matches"] = len(rows)
        scores: dict[str, float] = {}
        for index, row in enumerate(rows, start=1):
            scores[str(row["item_id"])] = round(1.0 / index, 3)
        return scores, diagnostics

    def _matches_search_filters(self, item: dict[str, Any], filters: dict[str, str]) -> bool:
        category = filters.get("category")
        if category and str(item.get("category") or "").lower() != category.lower():
            return False
        project = filters.get("project")
        if project and str(item.get("project") or "").lower() != project.lower():
            return False
        tag = filters.get("tag")
        if tag:
            tags = item.get("tags") or []
            if tag not in tags:
                return False
        return True

    def associated_items(self, item_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT i.*, l.link_type, l.from_item_id, l.to_item_id, l.created_at AS link_created_at
            FROM links l
            JOIN items i ON i.id = CASE
                WHEN l.from_item_id = ? THEN l.to_item_id
                ELSE l.from_item_id
            END
            WHERE l.from_item_id = ? OR l.to_item_id = ?
            ORDER BY CASE WHEN l.link_type = 'near_duplicate' THEN 1 ELSE 0 END, l.created_at DESC
            """,
            (item_id, item_id, item_id),
        ).fetchall()
        associated: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            item = self._row_to_item(row, include_content=False)
            if item["id"] in seen:
                continue
            seen.add(item["id"])
            item["link_type"] = row["link_type"]
            item["link_direction"] = "outgoing" if row["from_item_id"] == item_id else "incoming"
            item["link_created_at"] = row["link_created_at"]
            associated.append(item)
        for row, link_type in self._neighbor_capture_rows(item_id):
            if row["id"] in seen:
                continue
            item = self._row_to_item(row, include_content=False)
            seen.add(item["id"])
            item["link_type"] = link_type
            item["link_direction"] = "chronological"
            item["link_created_at"] = row["created_at"]
            associated.append(item)
        return associated

    def _neighbor_capture_rows(self, item_id: str) -> list[tuple[sqlite3.Row, str]]:
        root = self.conn.execute("SELECT id, project, created_at FROM items WHERE id = ?", (item_id,)).fetchone()
        if not root:
            return []
        project = root["project"]
        project_clause = "project IS NULL" if project is None else "project = ?"
        params_before: list[Any] = []
        params_after: list[Any] = []
        if project is not None:
            params_before.append(project)
            params_after.append(project)
        params_before.extend([root["created_at"], item_id])
        params_after.extend([root["created_at"], item_id])

        before = self.conn.execute(
            f"""
            SELECT * FROM items
            WHERE {project_clause} AND created_at < ? AND id != ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            tuple(params_before),
        ).fetchone()
        after = self.conn.execute(
            f"""
            SELECT * FROM items
            WHERE {project_clause} AND created_at > ? AND id != ?
            ORDER BY created_at ASC, rowid ASC
            LIMIT 1
            """,
            tuple(params_after),
        ).fetchone()

        neighbors: list[tuple[sqlite3.Row, str]] = []
        if before:
            neighbors.append((before, "previous_capture"))
        if after:
            neighbors.append((after, "next_capture"))
        return neighbors

    def record_export(self, label: str, bundle_hash: str, manifest: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO safe_exports (id, label, bundle_hash, manifest_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), label, bundle_hash, json.dumps(manifest, sort_keys=True), utc_now_iso()),
        )
        self._event("export.previewed", None, {"label": label, "bundle_hash": bundle_hash})
        self.conn.commit()

    def import_redacted_item(self, entry: dict[str, Any], *, source_label: str) -> dict[str, Any]:
        created = entry.get("created_at") or utc_now_iso()
        digest = str(entry["content_hash"])
        family_id = self._family_for_hash(digest, created)
        item_id = str(entry.get("id") or uuid.uuid4())
        if self.conn.execute("SELECT 1 FROM items WHERE id = ?", (item_id,)).fetchone():
            item_id = str(uuid.uuid4())

        preview = str(entry.get("preview") or "")
        category = str(entry.get("category") or "notes")
        sensitivity = str(entry.get("sensitivity") or "safe")
        project = entry.get("project")
        facets = dict(entry.get("facets") or {})
        facets.update(
            {
                "source": "safe_import",
                "imported_from": source_label,
                "redacted_restore": True,
            }
        )
        analysis = {
            "category": category,
            "sensitivity": sensitivity,
            "preview": preview,
            "summary": preview[:180],
            "content_hash": digest,
            "facets": facets,
            "chunks": list(entry.get("chunk_manifest") or []),
        }
        self.conn.execute(
            """
            INSERT INTO items (
                id, content, preview, summary, category, sensitivity, content_hash,
                family_id, project, source, analysis_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                preview,
                preview,
                preview[:180],
                category,
                sensitivity,
                digest,
                family_id,
                project,
                "safe_import",
                json.dumps(analysis, sort_keys=True),
                created,
                utc_now_iso(),
            ),
        )
        self.conn.execute(
            "INSERT INTO receipts (id, item_id, source, content_hash, path, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, "safe_import", digest, None, utc_now_iso()),
        )
        for key, value in facets.items():
            values = value if isinstance(value, list) else [value]
            for facet_value in values:
                if facet_value is not None:
                    self.conn.execute(
                        "INSERT INTO facets (item_id, key, value) VALUES (?, ?, ?)",
                        (item_id, key, str(facet_value)),
                    )
        self.conn.execute(
            "INSERT INTO summaries (id, item_id, kind, summary, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), item_id, "imported_redacted", preview[:180], utc_now_iso()),
        )
        self.conn.execute(
            "INSERT INTO item_fts (item_id, content, preview, category, project, facets) VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, preview, preview, category, project or "", json.dumps(analysis["facets"], sort_keys=True)),
        )
        self._event(
            "item.imported_redacted",
            item_id,
            {"source_label": source_label, "content_hash": digest, "category": category},
        )
        self.conn.commit()
        return self.get_item(item_id)

    def _row_to_item(self, row: sqlite3.Row, *, include_content: bool = True) -> dict[str, Any]:
        analysis = json.loads(row["analysis_json"])
        item = {
            "id": row["id"],
            "preview": row["preview"],
            "summary": row["summary"],
            "category": row["category"],
            "sensitivity": row["sensitivity"],
            "content_hash": row["content_hash"],
            "family_id": row["family_id"],
            "project": row["project"],
            "source": row["source"],
            "facets": analysis.get("facets", {}),
            "chunks": self._safe_chunks(analysis.get("chunks") or []),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        item["risk_class"] = str(item["facets"].get("risk_class") or ("sensitive" if row["sensitivity"] == "sensitive" else "safe"))
        raw_risk_reasons = item["facets"].get("risk_reasons") or []
        if not isinstance(raw_risk_reasons, list):
            raw_risk_reasons = [str(raw_risk_reasons)]
        item["risk_reasons"] = [str(reason) for reason in raw_risk_reasons]
        raw_tags = item["facets"].get("tags") or []
        if not isinstance(raw_tags, list):
            raw_tags = [str(raw_tags)]
        item["tags"] = [_normalize_tag(tag) for tag in raw_tags if _normalize_tag(tag)]
        if include_content and row["sensitivity"] != "sensitive":
            item["content"] = row["content"]
        replacement = self.replacement_for_item(row["id"])
        if replacement:
            item["deprecated"] = True
            item["successor_id"] = replacement["new_item_id"]
            item["replacement_reason"] = replacement["reason"]
            item["successor"] = replacement["successor"]
        else:
            item["deprecated"] = False
            item["successor_id"] = None
        facets = item["facets"]
        if facets.get("suggested_category"):
            item["filing_suggestion"] = {
                "target_category": facets.get("suggested_category"),
                "status": facets.get("filing_suggestion_status", "pending"),
                "reason": facets.get("filing_suggestion_reason", "suggested filing"),
                "confidence": facets.get("filing_suggestion_confidence", "unknown"),
            }
        item["next_suggestions"] = self._next_suggestions_for_item(row, item)
        return item

    def _next_suggestions_for_item(self, row: sqlite3.Row, item: dict[str, Any]) -> list[dict[str, Any]]:
        suggestions: list[dict[str, Any]] = []
        seen: set[str] = set()
        item_id = str(row["id"])

        def add(kind: str, label: str, reason: str, **extra: Any) -> None:
            if kind in seen:
                return
            seen.add(kind)
            suggestion = {
                "type": kind,
                "label": label,
                "reason": reason,
            }
            suggestion.update({key: value for key, value in extra.items() if value is not None})
            suggestions.append(suggestion)

        project = item.get("project")
        if project:
            add(
                "open_project_shelf",
                f"Open project shelf: {project}",
                "same-project captures are useful nearby context",
                project=project,
                category=item["category"],
            )

        facets = item.get("facets") or {}
        vendors = facets.get("vendors") or []
        if not isinstance(vendors, list):
            vendors = [str(vendors)]
        for vendor in vendors:
            vendor_name = str(vendor).strip()
            if vendor_name:
                add(
                    "search_vendor_context",
                    f"Find more {vendor_name} context",
                    "vendor facet was detected during capture",
                    query=f"{vendor_name} {item['category']}",
                    vendor=vendor_name,
                )
                break

        duplicate_count = self.conn.execute(
            "SELECT COUNT(*) AS count FROM items WHERE family_id = ? AND id != ?",
            (item["family_id"], item_id),
        ).fetchone()["count"]
        if int(duplicate_count) > 0:
            add(
                "review_duplicate_family",
                "Review duplicate family",
                f"{int(duplicate_count)} duplicate-family peer{'s' if int(duplicate_count) != 1 else ''} tracked",
                family_id=item["family_id"],
                count=int(duplicate_count),
            )

        linked_rows = self.conn.execute(
            """
            SELECT i.id, i.category, i.preview, l.link_type, l.from_item_id, l.to_item_id
            FROM links l
            JOIN items i ON i.id = CASE
                WHEN l.from_item_id = ? THEN l.to_item_id
                ELSE l.from_item_id
            END
            WHERE l.from_item_id = ? OR l.to_item_id = ?
            ORDER BY l.created_at DESC
            LIMIT 20
            """,
            (item_id, item_id, item_id),
        ).fetchall()
        if linked_rows:
            add(
                "open_linked_context",
                "Open linked context",
                f"{len(linked_rows)} directly linked item{'s' if len(linked_rows) != 1 else ''} nearby",
                item_id=item_id,
            )
        for linked in linked_rows:
            linked_category = str(linked["category"])
            link_type = str(linked["link_type"])
            if "screenshot" in linked_category or link_type == "screenshot_of":
                add(
                    "open_associated_screenshot",
                    "Open associated screenshot",
                    "a linked screenshot-like artifact is nearby",
                    item_id=linked["id"],
                    link_type=link_type,
                )
                break
        for linked in linked_rows:
            linked_category = str(linked["category"])
            if linked_category == "prompts":
                add(
                    "reuse_related_prompt",
                    "Reuse related prompt",
                    "a linked prompt is nearby",
                    item_id=linked["id"],
                )
                break

        if item.get("deprecated") and item.get("successor_id"):
            add(
                "use_successor",
                "Use successor item",
                str(item.get("replacement_reason") or "replacement is available"),
                item_id=item.get("successor_id"),
            )

        filing = item.get("filing_suggestion")
        if filing and filing.get("status") == "pending":
            add(
                "accept_filing_suggestion",
                f"Accept shelf: {filing.get('target_category')}",
                str(filing.get("reason") or "pending filing suggestion"),
                target_category=filing.get("target_category"),
            )

        risk_class = item.get("risk_class")
        if risk_class in {"sensitive", "blocked", "caution"}:
            add(
                "review_risk",
                f"Review {risk_class} item",
                "; ".join(item.get("risk_reasons") or []) or "risk class requires attention before reuse",
                risk_class=risk_class,
            )

        return suggestions[:6]

    def _safe_chunks(self, chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        safe: list[dict[str, Any]] = []
        for chunk in chunks:
            start = int(chunk["start"])
            end = int(chunk["end"])
            safe.append(
                {
                    "index": int(chunk["index"]),
                    "start": start,
                    "end": end,
                    "length": int(chunk.get("length", end - start)),
                    "overlap_before": int(chunk.get("overlap_before") or 0),
                    "hash": str(chunk["hash"]),
                }
            )
        return safe

    def _why(self, item: dict[str, Any], query: str, scores: dict[str, float], *, filters: dict[str, str] | None = None) -> list[str]:
        reasons = [f"matched score {scores['total']:.1f}"]
        for key, value in sorted((filters or {}).items()):
            reasons.append(f"filter {key}={value}")
        if item.get("deprecated"):
            reasons.append("deprecated: replacement available")
        if scores.get("exact", 0) > 0:
            reasons.append(f"exact signal {scores['exact']:.1f}")
        if scores.get("fts", 0) > 0:
            reasons.append(f"FTS signal {scores['fts']:.1f}")
        if scores.get("metadata", 0) > 0:
            reasons.append(f"metadata signal {scores['metadata']:.1f}")
        semantic = item.get("semantic") or {}
        if scores.get("semantic", 0) > 0:
            terms = ", ".join(semantic.get("matched_terms") or semantic.get("matched_groups") or [])
            suffix = f": {terms}" if terms else ""
            reasons.append(f"local semantic signal {scores['semantic']:.1f}{suffix}")
        if item["category"] == "API-Keys":
            reasons.append("category API-Keys")
        if "openrouter" in json.dumps(item["facets"]).lower() or "openrouter" in item["preview"].lower():
            reasons.append("OpenRouter facet")
        if "last 3 weeks" in query.lower():
            reasons.append("within requested time window")
        return reasons


def re_tokenize(text: str) -> list[str]:
    import re

    return re.findall(r"[a-z0-9_./-]+", text.lower())


def _fts_match_query(terms: list[str]) -> str:
    stop_words = {"last", "find", "added", "the", "with", "from", "that", "this"}
    safe_terms: list[str] = []
    seen: set[str] = set()
    for term in terms:
        for part in re.findall(r"[a-z0-9_]+", str(term).lower()):
            if len(part) <= 2 or part in stop_words or part in seen:
                continue
            seen.add(part)
            safe_terms.append(f"{part}*")
            if len(safe_terms) >= 12:
                break
        if len(safe_terms) >= 12:
            break
    return " OR ".join(safe_terms)


def _query_cutoff(lowered_query: str, *, now: str | None = None) -> datetime | None:
    anchor = _parse_iso(now or utc_now_iso())
    if re.search(r"\b(?:last|past|previous)\s+(?:three|3)\s+weeks?\b", lowered_query):
        return anchor - timedelta(weeks=3)
    if re.search(r"\b(?:three|3)[ -]?week\b", lowered_query):
        return anchor - timedelta(weeks=3)
    day_match = re.search(r"\b(?:last|past|previous|within)\s+(\d{1,3})\s+days?\b", lowered_query)
    if day_match:
        return anchor - timedelta(days=int(day_match.group(1)))
    week_match = re.search(r"\b(?:last|past|previous|within)\s+(\d{1,2})\s+weeks?\b", lowered_query)
    if week_match:
        return anchor - timedelta(weeks=int(week_match.group(1)))
    return None
