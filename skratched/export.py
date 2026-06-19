from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from .analyze import redact_text, resolve_safe_path, utc_now_iso
from .storage import SkratchedStore


SAFE_FACET_KEYS = {
    "artifact_hash",
    "byte_size",
    "chunk_count",
    "code_branch_count",
    "code_complexity",
    "code_imports",
    "code_language",
    "code_line_count",
    "code_symbols",
    "code_title",
    "filename",
    "filing_mode",
    "filing_suggestion_confidence",
    "filing_suggestion_reason",
    "filing_suggestion_status",
    "filing_suggestion_target",
    "length",
    "media_type",
    "redacted_restore",
    "reference_hosts",
    "reference_ids",
    "references",
    "risk_class",
    "risk_reasons",
    "source",
    "sql_complexity",
    "sql_normalized",
    "sql_operations",
    "sql_statement_count",
    "sql_tables",
    "sql_title",
    "tags",
    "vendors",
}


def _safe_chunk_manifest(item: dict[str, Any]) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    for chunk in item.get("chunks") or []:
        start = int(chunk["start"])
        end = int(chunk["end"])
        manifest.append(
            {
                "index": int(chunk["index"]),
                "start": start,
                "end": end,
                "length": end - start,
                "overlap_before": int(chunk.get("overlap_before") or 0),
                "hash": str(chunk["hash"]),
            }
        )
    return manifest


def _exportable_facets(item: dict[str, Any]) -> dict[str, Any]:
    facets = item.get("facets") or {}
    return {key: value for key, value in facets.items() if key in SAFE_FACET_KEYS}


def _export_entry_id(item: dict[str, Any]) -> str:
    material = {
        "id": str(item.get("id") or ""),
        "content_hash": str(item.get("content_hash") or ""),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return f"export_entry_{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"


def build_dry_run_export(store: SkratchedStore, *, label: str = "export-preview") -> dict[str, Any]:
    safe_label = redact_text(str(label or "export-preview"))
    items = store.list_items(limit=10_000)
    manifest_items = []
    for item in items:
        manifest_items.append(
            {
                "entry_id": _export_entry_id(item),
                "id": item["id"],
                "category": item["category"],
                "sensitivity": item["sensitivity"],
                "content_hash": item["content_hash"],
                "family_id": item["family_id"],
                "preview": item["preview"],
                "created_at": item["created_at"],
                "project": item["project"],
                "facets": _exportable_facets(item),
                "chunk_manifest": _safe_chunk_manifest(item),
            }
        )
    manifest = {
        "mode": "dry-run",
        "label": safe_label,
        "schema": "skratched.export.v1",
        "item_count": len(manifest_items),
        "items": manifest_items,
    }
    encoded = json.dumps(manifest, sort_keys=True).encode("utf-8")
    bundle_hash = hashlib.sha256(encoded).hexdigest()
    manifest["bundle_hash"] = bundle_hash
    store.record_export(safe_label, bundle_hash, manifest)
    return manifest


def _jsonl_line(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def build_jsonl_export(store: SkratchedStore, *, label: str = "export-preview") -> str:
    bundle = build_dry_run_export(store, label=label)
    header = {
        "record_type": "manifest",
        "schema": "skratched.export_jsonl.v1",
        "bundle_schema": bundle["schema"],
        "mode": bundle["mode"],
        "label": bundle["label"],
        "item_count": bundle["item_count"],
    }
    lines = [_jsonl_line(header)]
    for index, item in enumerate(bundle["items"]):
        lines.append(_jsonl_line({"record_type": "item", "index": index, "entry_id": item["entry_id"], "item": item}))
    footer = {
        "record_type": "footer",
        "bundle_hash": bundle["bundle_hash"],
        "item_count": bundle["item_count"],
    }
    lines.append(_jsonl_line(footer))
    return "\n".join(lines) + "\n"


def _safe_export_slug(label: str) -> str:
    safe = redact_text(str(label or "export"))
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", safe).strip("-._")
    return (slug[:48] or "export").lower()


def write_jsonl_export_file(
    store: SkratchedStore,
    *,
    label: str = "export-preview",
    directory: str | Path | None = None,
) -> dict[str, Any]:
    jsonl = build_jsonl_export(store, label=label)
    data = jsonl.encode("utf-8")
    bundle = parse_jsonl_export(jsonl)
    root = store.db_path.parent.resolve()
    if directory is None:
        exports_dir = root / "exports"
    else:
        exports_dir = resolve_safe_path(root, Path(directory))
    if exports_dir.exists() and (not exports_dir.is_dir() or exports_dir.is_symlink()):
        raise ValueError("export directory must be a real directory")
    exports_dir.mkdir(parents=True, exist_ok=True)
    exports_dir = exports_dir.resolve()
    if not exports_dir.is_relative_to(root):
        raise ValueError("export directory escapes the local data root")

    timestamp = utc_now_iso().replace(":", "").replace("-", "")
    filename = f"{timestamp}-{_safe_export_slug(str(bundle.get('label') or label))}-{bundle['bundle_hash'][:12]}.jsonl"
    path = exports_dir / filename
    if path.exists():
        path = exports_dir / f"{path.stem}-{uuid.uuid4().hex[:8]}{path.suffix}"
    tmp_path = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    file_hash = hashlib.sha256(data).hexdigest()
    report = {
        "schema": "skratched.export_file.v1",
        "format": "jsonl",
        "path": str(path),
        "bytes": len(data),
        "mode": "0600",
        "label": bundle["label"],
        "item_count": bundle["item_count"],
        "bundle_hash": bundle["bundle_hash"],
        "file_hash": file_hash,
    }
    store._event("export.file_written", None, report)
    store.conn.commit()
    return report


def parse_jsonl_export(text: str) -> dict[str, Any]:
    lines = [line for line in str(text).splitlines() if line.strip()]
    if len(lines) < 2:
        raise ValueError("JSONL export requires manifest and footer records")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSONL line {line_number} is invalid JSON") from exc
        if not isinstance(record, dict):
            raise ValueError(f"JSONL line {line_number} must be an object")
        records.append(record)

    header = records[0]
    footer = records[-1]
    if header.get("record_type") != "manifest" or header.get("schema") != "skratched.export_jsonl.v1":
        raise ValueError("unsupported JSONL export manifest")
    if footer.get("record_type") != "footer":
        raise ValueError("JSONL export footer is required")

    items = []
    for expected_index, record in enumerate(records[1:-1]):
        if record.get("record_type") != "item":
            raise ValueError(f"JSONL record {expected_index + 2} must be an item")
        if int(record.get("index", -1)) != expected_index:
            raise ValueError("JSONL item index mismatch")
        item = record.get("item")
        if not isinstance(item, dict):
            raise ValueError("JSONL item record must contain an object item")
        if record.get("entry_id") != item.get("entry_id"):
            raise ValueError("JSONL item entry_id mismatch")
        items.append(item)

    item_count = int(header.get("item_count", -1))
    if item_count != len(items) or int(footer.get("item_count", -1)) != len(items):
        raise ValueError("JSONL item count mismatch")

    bundle = {
        "mode": header.get("mode"),
        "label": header.get("label"),
        "schema": header.get("bundle_schema"),
        "item_count": len(items),
        "items": items,
        "bundle_hash": footer.get("bundle_hash"),
    }
    _verified_bundle(bundle)
    return bundle


def preview_redacted_jsonl(store: SkratchedStore, text: str) -> dict[str, Any]:
    return preview_redacted_bundle(store, parse_jsonl_export(text))


def import_redacted_jsonl(store: SkratchedStore, text: str) -> dict[str, Any]:
    return import_redacted_bundle(store, parse_jsonl_export(text))


def _verified_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    if bundle.get("schema") != "skratched.export.v1":
        raise ValueError("unsupported export schema")
    if bundle.get("mode") != "dry-run":
        raise ValueError("only redacted dry-run bundles can be imported safely")
    expected = bundle.get("bundle_hash")
    if not expected:
        raise ValueError("bundle_hash is required")

    without_hash = dict(bundle)
    without_hash.pop("bundle_hash", None)
    actual = hashlib.sha256(json.dumps(without_hash, sort_keys=True).encode("utf-8")).hexdigest()
    if actual != expected:
        raise ValueError("bundle_hash mismatch")
    for index, entry in enumerate(bundle.get("items", [])):
        expected_entry_id = _export_entry_id(entry)
        if entry.get("entry_id") is None:
            entry["entry_id"] = expected_entry_id
        elif entry.get("entry_id") != expected_entry_id:
            raise ValueError(f"entry_id mismatch for item {index}")
        _validate_chunk_manifest(entry, index=index)
    return without_hash


def _validate_chunk_manifest(entry: dict[str, Any], *, index: int) -> None:
    manifest = entry.get("chunk_manifest") or []
    if not isinstance(manifest, list):
        raise ValueError(f"chunk_manifest for item {index} must be a list")
    facets = entry.get("facets") or {}
    expected_count = int(facets.get("chunk_count") or 0)
    if expected_count != len(manifest):
        raise ValueError(f"chunk_manifest count mismatch for item {index}")
    previous_start = -1
    for chunk_index, chunk in enumerate(manifest):
        if not isinstance(chunk, dict):
            raise ValueError(f"chunk_manifest entry {chunk_index} for item {index} must be an object")
        required = {"index", "start", "end", "length", "overlap_before", "hash"}
        if set(chunk) != required:
            raise ValueError(f"chunk_manifest entry {chunk_index} for item {index} has invalid fields")
        start = int(chunk["start"])
        end = int(chunk["end"])
        length = int(chunk["length"])
        if int(chunk["index"]) != chunk_index:
            raise ValueError(f"chunk_manifest index mismatch for item {index}")
        if start < 0 or end <= start or length != end - start:
            raise ValueError(f"chunk_manifest boundary mismatch for item {index}")
        if start <= previous_start:
            raise ValueError(f"chunk_manifest ordering mismatch for item {index}")
        if chunk_index == 0 and int(chunk["overlap_before"]) != 0:
            raise ValueError(f"chunk_manifest overlap mismatch for item {index}")
        if chunk_index > 0 and int(chunk["overlap_before"]) < 0:
            raise ValueError(f"chunk_manifest overlap mismatch for item {index}")
        if not isinstance(chunk["hash"], str) or len(chunk["hash"]) != 64:
            raise ValueError(f"chunk_manifest hash mismatch for item {index}")
        int(chunk["hash"], 16)
        previous_start = start


def preview_redacted_bundle(store: SkratchedStore, bundle: dict[str, Any]) -> dict[str, Any]:
    _verified_bundle(bundle)
    entries = []
    seen_hashes: set[str] = set()
    duplicate_count = 0
    importable_count = 0
    for index, entry in enumerate(bundle.get("items", [])):
        digest = str(entry.get("content_hash") or "")
        existing_ids = store.item_ids_by_content_hash(digest) if digest else []
        if digest in seen_hashes:
            action = "skip_bundle_duplicate"
            duplicate_count += 1
        elif existing_ids:
            action = "skip_existing_duplicate"
            duplicate_count += 1
        else:
            action = "import"
            importable_count += 1
        if digest:
            seen_hashes.add(digest)
        entries.append(
            {
                "index": index,
                "entry_id": entry.get("entry_id"),
                "item_id": entry.get("id"),
                "content_hash": digest,
                "category": entry.get("category"),
                "sensitivity": entry.get("sensitivity"),
                "project": entry.get("project"),
                "preview": entry.get("preview"),
                "existing_item_ids": existing_ids,
                "action": action,
            }
        )

    return {
        "schema": "skratched.import_preview.v1",
        "bundle_label": bundle.get("label"),
        "bundle_hash": bundle.get("bundle_hash"),
        "item_count": len(entries),
        "importable_count": importable_count,
        "duplicate_count": duplicate_count,
        "entries": entries,
    }


def import_redacted_bundle(store: SkratchedStore, bundle: dict[str, Any]) -> dict[str, Any]:
    preview = preview_redacted_bundle(store, bundle)
    entries_by_index = {entry["index"]: entry for entry in preview["entries"]}

    imported = []
    skipped = []
    for index, entry in enumerate(bundle.get("items", [])):
        preview_entry = entries_by_index[index]
        if preview_entry["action"] != "import":
            skipped.append(preview_entry)
            continue
        imported.append(store.import_redacted_item(entry, source_label=str(bundle.get("label") or "import")))
    return {
        "schema": "skratched.import_report.v1",
        "imported": len(imported),
        "skipped": len(skipped),
        "item_ids": [item["id"] for item in imported],
        "preview": preview,
    }
