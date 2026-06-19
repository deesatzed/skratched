from __future__ import annotations

import copy
import json
import math
import re
from collections.abc import Callable
from typing import Any

from .analyze import redact_text


AI_ANALYSIS_SCHEMA = "skratched.ai_analysis.v1"
ALLOWED_CATEGORIES = {
    "notes",
    "prompts",
    "SQL queries",
    "API-Keys",
    "screenshots-work",
    "screenshots-products",
    "code",
    "commands",
    "research",
    "follow-up",
    "inbox",
}


def _normalize_tag(value: Any) -> str:
    tag = str(value).strip().lower()
    tag = re.sub(r"\s+", "-", tag)
    tag = re.sub(r"[^a-z0-9_./-]+", "", tag)
    tag = tag.strip("-._/")
    return tag[:64]


def _truncate(value: str, limit: int) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "..."


def _safe_string(value: Any, *, limit: int = 500) -> str:
    return _truncate(redact_text(str(value)), limit)


def _safe_payload(value: Any) -> Any:
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, list):
        return [_safe_payload(entry) for entry in value]
    if isinstance(value, tuple):
        return [_safe_payload(entry) for entry in value]
    if isinstance(value, dict):
        return {str(key): _safe_payload(entry) for key, entry in value.items()}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _safe_string(value)


def _fallback(
    deterministic: dict[str, Any],
    *,
    provider: str,
    error: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    merged = copy.deepcopy(deterministic)
    facets = dict(merged.get("facets") or {})
    facets["ai_status"] = "fallback"
    facets["ai_provider"] = provider
    facets["ai_error"] = _safe_payload(error)
    merged["facets"] = facets
    diagnostics = {
        "status": "fallback",
        "provider": provider,
        "error": facets["ai_error"],
    }
    return merged, diagnostics


def _validate_ai_payload(raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(raw, dict):
        return None, "AI analysis must be an object"
    if raw.get("schema") != AI_ANALYSIS_SCHEMA:
        return None, "AI analysis schema mismatch"

    payload: dict[str, Any] = {}
    category = raw.get("category")
    if category is not None:
        if not isinstance(category, str) or category not in ALLOWED_CATEGORIES:
            return None, "AI analysis category is not allowed"
        payload["category"] = category

    summary = raw.get("summary")
    if summary is not None:
        if not isinstance(summary, str):
            return None, "AI analysis summary must be a string"
        payload["summary"] = _safe_string(summary, limit=500)

    tags = raw.get("tags", [])
    if tags is None:
        tags = []
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        return None, "AI analysis tags must be a list of strings"
    payload["tags"] = [_normalize_tag(tag) for tag in tags if _normalize_tag(tag)]

    confidence = raw.get("confidence")
    if confidence is not None:
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            return None, "AI analysis confidence must be numeric"
        if not math.isfinite(confidence) or confidence < 0 or confidence > 1:
            return None, "AI analysis confidence must be between 0 and 1"
        payload["confidence"] = float(confidence)

    reason = raw.get("reason")
    if reason is not None:
        if not isinstance(reason, str):
            return None, "AI analysis reason must be a string"
        payload["reason"] = _safe_string(reason, limit=300)

    return payload, None


def apply_optional_ai_analysis(
    deterministic: dict[str, Any],
    raw: Any,
    *,
    provider: str = "optional",
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload, error = _validate_ai_payload(raw)
    if payload is None:
        detail = {"message": error, "raw": _safe_payload(raw)}
        return _fallback(deterministic, provider=provider, error=detail)

    merged = copy.deepcopy(deterministic)
    facets = dict(merged.get("facets") or {})

    existing_tags = facets.get("tags") or []
    if not isinstance(existing_tags, list):
        existing_tags = [str(existing_tags)]
    tags = sorted({_normalize_tag(tag) for tag in existing_tags if _normalize_tag(tag)} | set(payload["tags"]))
    facets["tags"] = tags
    facets["ai_status"] = "applied"
    facets["ai_provider"] = provider

    if "category" in payload:
        merged["category"] = payload["category"]
        facets["ai_suggested_category"] = payload["category"]
    if "summary" in payload:
        merged["summary"] = payload["summary"]
    if "confidence" in payload:
        facets["ai_confidence"] = f"{payload['confidence']:.2f}"
    if "reason" in payload:
        facets["ai_reason"] = payload["reason"]

    merged["facets"] = facets
    diagnostics = {
        "status": "applied",
        "provider": provider,
        "schema": AI_ANALYSIS_SCHEMA,
        "category": payload.get("category"),
    }
    if "confidence" in payload:
        diagnostics["confidence"] = payload["confidence"]
    if "reason" in payload:
        diagnostics["reason"] = payload["reason"]
    return merged, diagnostics


def run_optional_ai_analysis(
    text: str,
    deterministic: dict[str, Any],
    *,
    adapter: Callable[[str, dict[str, Any]], Any] | None = None,
    provider: str = "optional",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if adapter is None:
        return deterministic, None
    try:
        raw = adapter(text, copy.deepcopy(deterministic))
    except Exception as exc:
        return _fallback(deterministic, provider=provider, error=str(exc))
    try:
        json.dumps(_safe_payload(raw), sort_keys=True)
    except (TypeError, ValueError):
        return _fallback(deterministic, provider=provider, error="AI analysis could not be serialized safely")
    return apply_optional_ai_analysis(deterministic, raw, provider=provider)
