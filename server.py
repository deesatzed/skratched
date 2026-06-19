from __future__ import annotations

import argparse
import base64
import binascii
import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from skratched.analyze import redact_text
from skratched.config import load_config
from skratched.export import (
    build_dry_run_export,
    build_jsonl_export,
    import_redacted_bundle,
    import_redacted_jsonl,
    parse_jsonl_export,
    preview_redacted_bundle,
    preview_redacted_jsonl,
    write_jsonl_export_file,
)
from skratched.storage import SkratchedStore
from skratched.watcher import run_screenshot_watcher


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data"


class ApiValidationError(ValueError):
    pass


def _safe_error(message: object) -> dict:
    return {"error": redact_text(str(message))}


def _diagnostic_error(store: SkratchedStore, operation: str, message: object) -> dict:
    health = store.health_report()
    retry_options = [
        "Re-run import preview with an exported redacted bundle or JSONL payload.",
        "Validate that the bundle hash/footer is present and unchanged.",
        "Check /api/health before retrying if storage or index status is not ok.",
    ]
    return {
        "error": redact_text(str(message)),
        "diagnostic": {
            "schema": "skratched.error_diagnostic.v1",
            "operation": operation,
            "detail": redact_text(str(message)),
            "storage": health.get("storage", {}),
            "indexes": health.get("indexes", {}),
            "redaction": health.get("redaction", {}),
            "optional_ai": health.get("optional_ai", {}),
            "retry_options": retry_options,
        },
    }


def _required_string(payload: dict, field: str) -> str:
    if field not in payload:
        raise ApiValidationError(f"{field} is required")
    value = str(payload.get(field) or "").strip()
    if not value:
        raise ApiValidationError(f"{field} is required")
    return value


def _optional_string(payload: dict, field: str, default: str = "") -> str:
    value = payload.get(field)
    if value is None:
        return default
    return str(value)


def _bounded_int(payload: dict, field: str, *, default: int, minimum: int, maximum: int) -> int:
    raw = payload.get(field, default)
    if raw is None or raw == "":
        raw = default
    if isinstance(raw, bool):
        raise ApiValidationError(f"{field} must be an integer")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ApiValidationError(f"{field} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ApiValidationError(f"{field} must be between {minimum} and {maximum}")
    return value


def _bounded_float(payload: dict, field: str, *, default: float, minimum: float, maximum: float) -> float:
    raw = payload.get(field, default)
    if raw is None or raw == "":
        raw = default
    if isinstance(raw, bool):
        raise ApiValidationError(f"{field} must be a number")
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ApiValidationError(f"{field} must be a number") from exc
    if value < minimum or value > maximum:
        raise ApiValidationError(f"{field} must be between {minimum:g} and {maximum:g}")
    return value


def dispatch_api(store: SkratchedStore, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    parsed = urlparse(path)
    if method == "GET":
        if parsed.path == "/api/health":
            return 200, store.health_report()
        if parsed.path == "/api/items":
            return 200, {"items": store.list_items(limit=100)}
        if parsed.path == "/api/categories":
            return 200, {"categories": store.categories()}
        if parsed.path == "/api/tags":
            return 200, {"tags": store.tags()}
        if parsed.path == "/api/shelves":
            return 200, {"shelves": store.categories()}
        if parsed.path == "/api/summaries":
            return 200, store.memory_summaries()
        if parsed.path == "/api/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            return 200, {"query": query, "results": store.search(query)}
        if parsed.path == "/api/context":
            item_id = parse_qs(parsed.query).get("item_id", [""])[0]
            if not item_id:
                return 400, {"error": "item_id is required"}
            return 200, store.context_graph(item_id)
        if parsed.path == "/api/versions":
            item_id = parse_qs(parsed.query).get("item_id", [""])[0]
            if not item_id:
                return 400, {"error": "item_id is required"}
            try:
                return 200, store.version_history(item_id)
            except ValueError as exc:
                return 400, _safe_error(exc)
        if parsed.path == "/api/actions/propose":
            item_id = parse_qs(parsed.query).get("item_id", [""])[0]
            action = parse_qs(parsed.query).get("action", ["reuse"])[0]
            if not item_id:
                return 400, {"error": "item_id is required"}
            try:
                return 200, store.propose_item_action(item_id, action=action)
            except ValueError as exc:
                return 400, _safe_error(exc)
        if parsed.path == "/api/replacements":
            return 200, {"replacements": store.list_replacements(limit=100)}
        return 404, {"error": "not found"}

    if method != "POST":
        return 405, {"error": "method not allowed"}

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return 400, {"error": "request body must be a JSON object"}

    if parsed.path == "/api/capture":
        text = str(payload.get("text", ""))
        if not text.strip():
            return 400, {"error": "text is required"}
        try:
            item = store.capture(
                text,
                source=_optional_string(payload, "source", "manual") or "manual",
                project=_optional_string(payload, "project") or None,
                path=payload.get("path"),
                filing_mode=_optional_string(payload, "filing_mode", "auto") or "auto",
            )
        except ValueError as exc:
            return 400, _safe_error(exc)
        return 201, {"item": item}

    if parsed.path == "/api/capture-file":
        filename = _optional_string(payload, "filename").strip()
        encoded = str(payload.get("content_base64") or "")
        if not filename:
            return 400, {"error": "filename is required"}
        if not encoded:
            return 400, {"error": "content_base64 is required"}
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return 400, {"error": "content_base64 is invalid"}
        try:
            item = store.capture_artifact(
                filename=filename,
                content=content,
                media_type=_optional_string(payload, "media_type", "application/octet-stream") or "application/octet-stream",
                source=_optional_string(payload, "source", "file") or "file",
                project=_optional_string(payload, "project") or None,
            )
        except ValueError as exc:
            return 400, _safe_error(exc)
        return 201, {"item": item}

    if parsed.path == "/api/screenshots/scan":
        directory = _optional_string(payload, "directory").strip()
        if not directory:
            directory = str(Path.home() / "Desktop")
        try:
            report = store.scan_screenshot_watch(
                directory,
                project=_optional_string(payload, "project") or None,
                limit=_bounded_int(payload, "limit", default=10, minimum=1, maximum=100),
            )
        except (ApiValidationError, ValueError, OSError) as exc:
            return 400, _safe_error(exc)
        return 200, report

    if parsed.path == "/api/screenshots/watch-run":
        directory = _optional_string(payload, "directory").strip()
        if not directory:
            directory = str(Path.home() / "Desktop")
        try:
            max_cycles = _bounded_int(payload, "max_cycles", default=1, minimum=1, maximum=25)
            report = run_screenshot_watcher(
                store,
                directory,
                project=_optional_string(payload, "project") or None,
                interval_seconds=_bounded_float(payload, "interval_seconds", default=0, minimum=0, maximum=3600),
                limit=_bounded_int(payload, "limit", default=10, minimum=1, maximum=100),
                max_cycles=max_cycles,
            )
        except (ApiValidationError, ValueError, OSError) as exc:
            return 400, _safe_error(exc)
        return 200, report

    if parsed.path == "/api/workspace/scan-preview":
        root = _required_string(payload, "root")
        try:
            report = store.workspace_scan_preview(
                root,
                project=_optional_string(payload, "project") or None,
                type_filter=_optional_string(payload, "type", "all") or "all",
                filename=_optional_string(payload, "file") or None,
                since=_optional_string(payload, "since") or None,
                until=_optional_string(payload, "until") or None,
                stale=_optional_string(payload, "stale") or None,
                max_depth=_bounded_int(payload, "depth", default=5, minimum=0, maximum=25) if "depth" in payload else None,
                refresh=bool(payload.get("refresh")),
                limit=_bounded_int(payload, "limit", default=100, minimum=1, maximum=250),
            )
        except (ApiValidationError, ValueError, OSError) as exc:
            return 400, _safe_error(exc)
        return 200, report

    if parsed.path == "/api/workspace/capture":
        try:
            item = store.capture_workspace_candidate(
                _required_string(payload, "candidate_id"),
                project=_optional_string(payload, "project") or None,
                import_content=bool(payload.get("import_content")),
                local_unlock=bool(payload.get("local_unlock")),
            )
        except PermissionError as exc:
            return 403, _safe_error(exc)
        except (ApiValidationError, ValueError, OSError, KeyError) as exc:
            return 400, _safe_error(exc)
        return 201, {"item": item}

    if parsed.path == "/api/link":
        try:
            store.link_items(
                _required_string(payload, "from_item_id"),
                _required_string(payload, "to_item_id"),
                _optional_string(payload, "link_type", "associated_context") or "associated_context",
            )
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)
        return 200, {"ok": True}

    if parsed.path == "/api/shelves":
        try:
            shelf = store.ensure_shelf(
                _required_string(payload, "category"),
                reason=_optional_string(payload, "reason", "manual shelf") or "manual shelf",
            )
        except ValueError as exc:
            return 400, _safe_error(exc)
        return 201, {"shelf": shelf, "categories": store.categories()}

    if parsed.path == "/api/tags":
        try:
            raw_tags = payload.get("tags") or []
            if isinstance(raw_tags, str):
                raw_tags = raw_tags.split(",")
            if not isinstance(raw_tags, list):
                raise ApiValidationError("tags must be a list or comma-separated string")
            item = store.update_tags(
                _required_string(payload, "item_id"),
                [str(tag) for tag in raw_tags],
                reason=_optional_string(payload, "reason", "tag edit") or "tag edit",
            )
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)
        return 200, {"item": item, "tags": store.tags()}

    if parsed.path == "/api/items/edit":
        try:
            text = str(payload.get("text", ""))
            if not text.strip():
                return 400, {"error": "text is required"}
            item = store.edit_item(
                _required_string(payload, "item_id"),
                text,
                reason=_optional_string(payload, "reason", "edit") or "edit",
            )
            return 200, {"item": item, "history": store.version_history(str(payload.get("item_id")))}
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)

    if parsed.path == "/api/actions/check":
        try:
            return 200, store.check_item_action(
                _required_string(payload, "item_id"),
                action=_optional_string(payload, "action", "reuse") or "reuse",
            )
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)

    if parsed.path == "/api/actions/apply":
        try:
            return 200, store.apply_item_action(
                _required_string(payload, "item_id"),
                action=_optional_string(payload, "action", "reuse") or "reuse",
                approved=bool(payload.get("approved")),
                reason=_optional_string(payload, "reason", "apply action") or "apply action",
            )
        except PermissionError as exc:
            return 403, _safe_error(exc)
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)

    if parsed.path == "/api/export/dry-run":
        bundle = build_dry_run_export(store, label=_optional_string(payload, "label", "manual-preview") or "manual-preview")
        return 200, bundle

    if parsed.path == "/api/export/jsonl":
        jsonl = build_jsonl_export(store, label=_optional_string(payload, "label", "manual-jsonl") or "manual-jsonl")
        bundle = parse_jsonl_export(jsonl)
        return 200, {
            "schema": "skratched.export_jsonl.v1",
            "label": bundle["label"],
            "item_count": bundle["item_count"],
            "bundle_hash": bundle["bundle_hash"],
            "jsonl": jsonl,
        }

    if parsed.path == "/api/export/jsonl/save":
        try:
            report = write_jsonl_export_file(store, label=_optional_string(payload, "label", "manual-jsonl") or "manual-jsonl")
        except (ValueError, OSError) as exc:
            return 400, _safe_error(exc)
        return 200, report

    if parsed.path == "/api/import/redacted":
        try:
            report = import_redacted_bundle(store, payload)
        except ValueError as exc:
            return 400, _diagnostic_error(store, "import.apply", exc)
        return 201, report

    if parsed.path == "/api/import/jsonl":
        try:
            report = import_redacted_jsonl(store, _required_string(payload, "jsonl"))
        except (ApiValidationError, ValueError) as exc:
            return 400, _diagnostic_error(store, "import.jsonl_apply", exc)
        return 201, report

    if parsed.path == "/api/import/preview":
        try:
            preview = preview_redacted_bundle(store, payload)
        except ValueError as exc:
            return 400, _diagnostic_error(store, "import.preview", exc)
        return 200, preview

    if parsed.path == "/api/import/jsonl/preview":
        try:
            preview = preview_redacted_jsonl(store, _required_string(payload, "jsonl"))
        except (ApiValidationError, ValueError) as exc:
            return 400, _diagnostic_error(store, "import.jsonl_preview", exc)
        return 200, preview

    if parsed.path == "/api/reveal":
        try:
            item = store.reveal_item(
                _required_string(payload, "item_id"),
                local_unlock=bool(payload.get("local_unlock")),
                reason=_optional_string(payload, "reason", "local reveal") or "local reveal",
            )
        except PermissionError as exc:
            return 403, _safe_error(exc)
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)
        return 200, {"item": item}

    if parsed.path == "/api/replace":
        try:
            old_item_id = _required_string(payload, "old_item_id")
            store.mark_replacement(
                old_item_id,
                _required_string(payload, "new_item_id"),
                reason=_optional_string(payload, "reason", "replacement") or "replacement",
            )
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)
        return 200, store.context_graph(old_item_id)

    if parsed.path == "/api/refile":
        try:
            item = store.refile_item(
                _required_string(payload, "item_id"),
                _required_string(payload, "category"),
                reason=_optional_string(payload, "reason", "manual filing") or "manual filing",
            )
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)
        return 200, {"item": item}

    if parsed.path == "/api/filing-suggestions/accept":
        try:
            item = store.accept_filing_suggestion(
                _required_string(payload, "item_id"),
                reason=_optional_string(payload, "reason", "accept filing suggestion") or "accept filing suggestion",
            )
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)
        return 200, {"item": item}

    if parsed.path == "/api/undo-filing":
        try:
            item = store.undo_last_filing(
                _required_string(payload, "item_id"),
                reason=_optional_string(payload, "reason", "undo filing") or "undo filing",
            )
        except (ApiValidationError, ValueError) as exc:
            return 400, _safe_error(exc)
        return 200, {"item": item}

    return 404, {"error": "not found"}


class SkratchedHandler(BaseHTTPRequestHandler):
    server_version = "Skratched/0.1"

    @property
    def store(self) -> SkratchedStore:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        # Avoid logging request bodies or captured content.
        print("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            status, body = dispatch_api(self.store, "GET", self.path)
            self._json(body, status=status)
            return
        self._static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            try:
                payload = self._body_json()
            except ValueError as exc:
                self._json(_safe_error(exc), status=HTTPStatus.BAD_REQUEST)
                return
            status, body = dispatch_api(self.store, "POST", self.path, payload)
            self._json(body, status=status)
            return
        self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _body_json(self) -> dict:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def _json(self, payload: dict, status: int | HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(int(status))
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, path: str) -> None:
        if path in {"", "/"}:
            target = STATIC / "index.html"
        else:
            target = (STATIC / path.lstrip("/")).resolve()
            try:
                target.relative_to(STATIC.resolve())
            except ValueError:
                self._json({"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
                return
        if not target.exists() or not target.is_file():
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def build_server(host: str, port: int, db_path: Path) -> HTTPServer:
    server = HTTPServer((host, port), SkratchedHandler)
    server.store = SkratchedStore(db_path)  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Skratched app.")
    parser.add_argument("--config", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--db", dest="db_path", default=None)
    args = parser.parse_args()

    cli = {key: value for key, value in vars(args).items() if value is not None}
    config = load_config(cli=cli, base_dir=ROOT)

    server = build_server(config.host, config.port, config.db_path)
    print(f"Skratched running at http://{config.host}:{config.port}")
    print(f"SQLite store: {server.store.db_path}")  # type: ignore[attr-defined]
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.store.close()  # type: ignore[attr-defined]
        server.server_close()


if __name__ == "__main__":
    main()
