from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skratched.storage import SkratchedStore


QUERY = "find my last OpenRouter API keys added in the last 3 weeks"
NOW = "2026-06-18T12:00:00Z"


def run_demo() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="skratched-demo-") as tmp:
        store = SkratchedStore(Path(tmp) / "skratched.db")
        try:
            stale = store.capture(
                "OPENROUTER_API_KEY=sk-or-v1-demostaleaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                source="clipboard",
                project="old-project",
                created_at="2026-05-01T12:00:00Z",
            )
            note = store.capture(
                "Recent OpenRouter key belongs with the local proxy config and routing smoke test.",
                source="note",
                project="skratched",
                created_at="2026-06-16T12:00:00Z",
            )
            recent = store.capture(
                "OPENROUTER_API_KEY=sk-or-v1-demorecentbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                source="clipboard",
                project="skratched",
                created_at="2026-06-17T12:00:00Z",
            )
            store.link_items(recent["id"], note["id"], "associated_context")

            results = store.search(QUERY, now=NOW)
            top = results[0] if results else {}
            associated = top.get("associated", []) if isinstance(top, dict) else []
            encoded = json.dumps({"results": results, "stale": stale, "recent": recent})
            raw_secret_redacted = "sk-or-v1-demo" not in encoded
            stale_key_excluded = stale["id"] not in {item["id"] for item in results}
            associated_ids = {item["id"] for item in associated}
            associated_link_types = sorted({str(item.get("link_type")) for item in associated})
            passed = bool(
                top
                and top.get("id") == recent["id"]
                and top.get("category") == "API-Keys"
                and note["id"] in associated_ids
                and stale_key_excluded
                and raw_secret_redacted
            )
            return {
                "schema": "skratched.demo_flow.v1",
                "passed": passed,
                "query": QUERY,
                "now": NOW,
                "top": {
                    "id": top.get("id"),
                    "category": top.get("category"),
                    "preview": top.get("preview"),
                    "why": top.get("why", []),
                },
                "associated_count": len(associated),
                "associated_link_types": associated_link_types,
                "stale_key_excluded": stale_key_excluded,
                "raw_secret_redacted": raw_secret_redacted,
            }
        finally:
            store.close()


def main() -> int:
    payload = run_demo()
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
