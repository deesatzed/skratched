import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from skratched.analyze import analyze_capture, chunk_text, redact_text, resolve_safe_path
from skratched.ai import apply_optional_ai_analysis
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


class AnalysisTests(unittest.TestCase):
    def test_openrouter_key_is_redacted_and_classified(self):
        text = "OPENROUTER_API_KEY=sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        analysis = analyze_capture(text, source="clipboard")

        self.assertEqual(analysis["category"], "API-Keys")
        self.assertEqual(analysis["sensitivity"], "sensitive")
        self.assertIn("openrouter", analysis["facets"]["vendors"])
        self.assertNotIn("sk-or-v1-aaaaaaaa", analysis["preview"])
        self.assertIn("[REDACTED:openrouter_key]", analysis["preview"])

    def test_redaction_preserves_placeholders(self):
        text = "Use OPENROUTER_API_KEY=<OPENROUTER_API_KEY> not sk-or-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        redacted = redact_text(text)

        self.assertIn("<OPENROUTER_API_KEY>", redacted)
        self.assertNotIn("sk-or-v1-bbbbb", redacted)

    def test_redaction_covers_env_sql_and_shell_secret_variants(self):
        cases = [
            (
                "DATABASE_URL=postgresql://app_user:dbSecretPass123@db.local:5432/app",
                ["dbSecretPass123"],
                "[REDACTED:credentials]",
            ),
            (
                'psql "postgresql://admin:sqlSecret456@127.0.0.1:5432/app" -c "select 1"',
                ["sqlSecret456"],
                "[REDACTED:credentials]",
            ),
            (
                'curl -H "Authorization: Bearer bearer_secret_token_1234567890abcdef" https://example.test',
                ["bearer_secret_token_1234567890abcdef"],
                "[REDACTED:bearer_token]",
            ),
            (
                "PGPASSWORD=pgEnvSecret123 psql postgresql://db.local/app",
                ["pgEnvSecret123"],
                "[REDACTED:secret]",
            ),
            (
                "mysql --password=shellSecret7890 --host db.local --user app",
                ["shellSecret7890"],
                "[REDACTED:secret]",
            ),
        ]

        for text, raw_values, marker in cases:
            with self.subTest(text=text):
                redacted = redact_text(text)
                self.assertIn(marker, redacted)
                for raw in raw_values:
                    self.assertNotIn(raw, redacted)

    def test_redaction_covers_json_yaml_header_and_query_secret_variants(self):
        cases = [
            (
                '{"api_key": "jsonSecretToken1234567890", "mode": "local"}',
                ["jsonSecretToken1234567890"],
                "[REDACTED:secret]",
            ),
            (
                "token: yamlSecretToken1234567890\nsafe: true",
                ["yamlSecretToken1234567890"],
                "[REDACTED:secret]",
            ),
            (
                'curl -H "X-API-Key: headerSecretToken1234567890" https://example.test',
                ["headerSecretToken1234567890"],
                "[REDACTED:secret]",
            ),
            (
                "https://api.example.test/v1/models?api_key=querySecretToken1234567890&project=demo",
                ["querySecretToken1234567890"],
                "[REDACTED:secret]",
            ),
        ]

        for text, raw_values, marker in cases:
            with self.subTest(text=text):
                redacted = redact_text(text)
                self.assertIn(marker, redacted)
                for raw in raw_values:
                    self.assertNotIn(raw, redacted)

    def test_url_references_get_stable_redacted_ids(self):
        raw_secret = "querySecretToken1234567890"
        first = analyze_capture(
            f"Read https://docs.example.test/guide?api_key={raw_secret}&page=1 before filing.",
            source="clipboard",
        )
        second = analyze_capture(
            f"Later citation: https://DOCS.example.test/guide?api_key={raw_secret}&page=1.",
            source="manual",
        )

        first_refs = first["facets"]["references"]
        second_refs = second["facets"]["references"]
        encoded = json.dumps({"first": first, "second": second})

        self.assertEqual(len(first_refs), 1)
        self.assertEqual(first_refs[0]["kind"], "url")
        self.assertEqual(first_refs[0]["host"], "docs.example.test")
        self.assertTrue(first_refs[0]["id"].startswith("ref_"))
        self.assertEqual(first_refs[0]["id"], second_refs[0]["id"])
        self.assertIn("[REDACTED:secret]", first_refs[0]["url"])
        self.assertNotIn(raw_secret, encoded)

    def test_generic_secret_capture_is_sensitive_and_not_returned_by_default(self):
        text = """
        DATABASE_URL=postgresql://app_user:dbSecretPass123@db.local:5432/app
        curl -H "Authorization: Bearer bearer_secret_token_1234567890abcdef" https://example.test
        """

        analysis = analyze_capture(text, source="clipboard")

        encoded = json.dumps(analysis)
        self.assertEqual(analysis["category"], "API-Keys")
        self.assertEqual(analysis["sensitivity"], "sensitive")
        self.assertIn("secret", analysis["facets"]["tags"])
        self.assertIn("[REDACTED:credentials]", analysis["preview"])
        self.assertIn("[REDACTED:bearer_token]", analysis["preview"])
        self.assertNotIn("dbSecretPass123", encoded)
        self.assertNotIn("bearer_secret_token", encoded)

    def test_analysis_assigns_explicit_risk_classes(self):
        cases = [
            ("Meeting note about tomorrow's launch", "safe"),
            ("select * from users where active = true;", "caution"),
            ("OPENROUTER_API_KEY=sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sensitive"),
            ("rm -rf / --no-preserve-root", "blocked"),
        ]

        for text, expected in cases:
            with self.subTest(expected=expected):
                analysis = analyze_capture(text, source="clipboard")
                self.assertEqual(analysis["facets"]["risk_class"], expected)
                self.assertIn(expected, {"safe", "caution", "sensitive", "blocked"})
                self.assertTrue(analysis["facets"]["risk_reasons"])

    def test_optional_ai_analysis_validates_schema_and_preserves_secret_safety(self):
        deterministic = analyze_capture(
            "OPENROUTER_API_KEY=sk-or-v1-aivalidationaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
        )

        merged, diagnostics = apply_optional_ai_analysis(
            deterministic,
            {
                "schema": "skratched.ai_analysis.v1",
                "category": "research",
                "summary": "OpenRouter credential for local model routing",
                "tags": ["Model Routing", "openrouter"],
                "confidence": 0.82,
                "reason": "model recognized routing context",
            },
            provider="fake-local",
        )

        encoded = json.dumps({"merged": merged, "diagnostics": diagnostics})
        self.assertEqual(merged["category"], "research")
        self.assertEqual(merged["sensitivity"], "sensitive")
        self.assertEqual(merged["facets"]["ai_status"], "applied")
        self.assertEqual(merged["facets"]["ai_provider"], "fake-local")
        self.assertIn("model-routing", merged["facets"]["tags"])
        self.assertIn("[REDACTED:openrouter_key]", merged["preview"])
        self.assertNotIn("sk-or-v1-aivalidation", encoded)

    def test_optional_ai_analysis_invalid_schema_falls_back_with_redacted_diagnostic(self):
        deterministic = analyze_capture(
            "OPENROUTER_API_KEY=sk-or-v1-aiinvalidbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            source="clipboard",
        )

        merged, diagnostics = apply_optional_ai_analysis(
            deterministic,
            {"schema": "wrong", "error": "sk-or-v1-aiinvalidbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            provider="fake-local",
        )

        encoded = json.dumps({"merged": merged, "diagnostics": diagnostics})
        self.assertEqual(merged["category"], "API-Keys")
        self.assertEqual(merged["facets"]["ai_status"], "fallback")
        self.assertEqual(diagnostics["status"], "fallback")
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-aiinvalid", encoded)

    def test_chunk_text_uses_overlap_boundaries(self):
        text = "abcdefghijklmnopqrstuvwxyz"

        chunks = chunk_text(text, chunk_size=10, overlap=3)

        self.assertEqual(chunks[0]["start"], 0)
        self.assertEqual(chunks[0]["end"], 10)
        self.assertEqual(chunks[1]["start"], 7)
        self.assertEqual(chunks[-1]["text"], text[chunks[-1]["start"] : chunks[-1]["end"]])

    def test_safe_path_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            link = root / "escape"
            link.symlink_to(outside, target_is_directory=True)

            with self.assertRaises(ValueError):
                resolve_safe_path(root, "escape/secret.txt")

    def test_sql_analysis_extracts_entities_title_and_complexity(self):
        text = """
        WITH recent_orders AS (
            SELECT user_id, count(*) AS order_count
            FROM orders
            WHERE created_at > now() - interval '30 days'
            GROUP BY user_id
        )
        SELECT u.id, u.email, r.order_count
        FROM users u
        JOIN recent_orders r ON r.user_id = u.id
        WHERE u.active = true;
        UPDATE users SET last_seen_at = now() WHERE id = 42;
        """

        analysis = analyze_capture(text, source="clipboard")
        facets = analysis["facets"]

        self.assertEqual(analysis["category"], "SQL queries")
        self.assertEqual(facets["sql_statement_count"], 2)
        self.assertEqual(facets["sql_operations"], ["select", "update"])
        self.assertEqual(facets["sql_tables"], ["orders", "recent_orders", "users"])
        self.assertEqual(facets["sql_complexity"], "complex")
        self.assertIn("join", facets["tags"])
        self.assertIn("update", facets["tags"])
        self.assertEqual(facets["sql_title"], "SELECT users, orders, recent_orders")
        self.assertTrue(facets["sql_normalized"].startswith("with recent_orders as"))
        self.assertNotIn("\n", facets["sql_normalized"])

    def test_sql_normalization_is_stable_across_whitespace_variants(self):
        left = "SELECT id, email FROM users WHERE active = true;"
        right = "  select  id,   email\nfrom   users\nwhere active = true ;  "

        left_analysis = analyze_capture(left, source="clipboard")
        right_analysis = analyze_capture(right, source="clipboard")

        self.assertEqual(left_analysis["facets"]["sql_normalized"], right_analysis["facets"]["sql_normalized"])
        self.assertEqual(left_analysis["facets"]["sql_tables"], ["users"])
        self.assertEqual(right_analysis["facets"]["sql_tables"], ["users"])

    def test_python_code_analysis_extracts_language_symbols_and_imports(self):
        text = """
        import json
        from pathlib import Path

        class MemoryRouter:
            def __init__(self, root):
                self.root = Path(root)

            def route_item(self, item):
                if item.get("category") == "API-Keys":
                    return "secure"
                return "normal"
        """

        analysis = analyze_capture(text, source="clipboard", filename="router.py")
        facets = analysis["facets"]

        self.assertEqual(analysis["category"], "code")
        self.assertEqual(facets["code_language"], "python")
        self.assertEqual(facets["code_symbols"], ["MemoryRouter", "__init__", "route_item"])
        self.assertEqual(facets["code_imports"], ["json", "pathlib.Path"])
        self.assertEqual(facets["code_complexity"], "moderate")
        self.assertEqual(facets["code_title"], "python: MemoryRouter, __init__, route_item")
        self.assertIn("python", facets["tags"])
        self.assertIn("class", facets["tags"])

    def test_javascript_code_analysis_extracts_language_and_symbols(self):
        text = """
        import { readFileSync } from "fs";
        const normalizeTag = (value) => value.trim().toLowerCase();
        function renderCard(item) {
          return `${item.category}: ${item.preview}`;
        }
        """

        analysis = analyze_capture(text, source="clipboard", filename="ui.js")
        facets = analysis["facets"]

        self.assertEqual(analysis["category"], "code")
        self.assertEqual(facets["code_language"], "javascript")
        self.assertEqual(facets["code_symbols"], ["normalizeTag", "renderCard"])
        self.assertEqual(facets["code_imports"], ["fs"])
        self.assertEqual(facets["code_complexity"], "simple")
        self.assertEqual(facets["code_title"], "javascript: normalizeTag, renderCard")

    def test_typescript_code_analysis_handles_typed_arrow_functions(self):
        text = """
        import type { MemoryItem } from "./types";
        import { rankItems } from "./rank";

        export const scoreMemory = (item: MemoryItem): number => item.weight ?? 0;
        export function renderHint(item: MemoryItem): string {
          return `${item.category}:${item.preview}`;
        }
        """

        analysis = analyze_capture(text, source="clipboard", filename="memory.ts")
        facets = analysis["facets"]

        self.assertEqual(analysis["category"], "code")
        self.assertEqual(facets["code_language"], "typescript")
        self.assertEqual(facets["code_symbols"], ["scoreMemory", "renderHint"])
        self.assertEqual(facets["code_imports"], ["./types", "./rank"])
        self.assertEqual(facets["code_title"], "typescript: scoreMemory, renderHint")
        self.assertIn("typescript", facets["tags"])

    def test_shell_code_analysis_extracts_function_and_commands(self):
        text = """
        #!/bin/zsh
        set -euo pipefail

        sync_memory() {
          rsync -a "$SRC/" "$DST/"
          python -m skratched.watcher "$DST" --max-cycles 1
        }
        """

        analysis = analyze_capture(text, source="clipboard", filename="sync.sh")
        facets = analysis["facets"]

        self.assertEqual(analysis["category"], "code")
        self.assertEqual(facets["code_language"], "shell")
        self.assertEqual(facets["code_symbols"], ["sync_memory"])
        self.assertEqual(facets["code_imports"], ["set", "rsync", "python"])
        self.assertEqual(facets["code_title"], "shell: sync_memory")
        self.assertIn("shell", facets["tags"])

    def test_malformed_javascript_code_does_not_invent_symbols(self):
        text = """
        const config = {
          endpoint: "/api/search",
          retry: true
        """

        analysis = analyze_capture(text, source="clipboard", filename="broken.js")
        facets = analysis["facets"]

        self.assertEqual(analysis["category"], "code")
        self.assertEqual(facets["code_language"], "javascript")
        self.assertEqual(facets["code_symbols"], [])
        self.assertEqual(facets["code_imports"], [])
        self.assertEqual(facets["code_title"], "javascript: javascript")

    def test_code_metadata_is_stable_across_whitespace_variants(self):
        compact = 'import { rankItems } from "./rank";\nexport const scoreMemory=(item: MemoryItem): number=>item.weight ?? 0;\n'
        spaced = """
        import { rankItems } from "./rank";

        export const scoreMemory = (
          item: MemoryItem
        ): number => item.weight ?? 0;
        """

        compact_analysis = analyze_capture(compact, source="clipboard", filename="memory.ts")
        spaced_analysis = analyze_capture(spaced, source="clipboard", filename="memory.ts")

        self.assertEqual(compact_analysis["facets"]["code_language"], spaced_analysis["facets"]["code_language"])
        self.assertEqual(compact_analysis["facets"]["code_symbols"], spaced_analysis["facets"]["code_symbols"])
        self.assertEqual(compact_analysis["facets"]["code_imports"], spaced_analysis["facets"]["code_imports"])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "skratched.db"
        self.store = SkratchedStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_structured_secret_capture_is_redacted_in_item_and_export_payloads(self):
        text = """
        {
          "api_key": "jsonSecretToken1234567890",
          "token": "jsonBearerToken1234567890"
        }
        curl -H "X-API-Key: headerSecretToken1234567890" \
          "https://api.example.test/v1/models?api_key=querySecretToken1234567890&project=demo"
        """

        analysis = analyze_capture(text, source="clipboard", filename="config.json")
        item = self.store.capture(text, source="clipboard", path="config.json")
        bundle = build_dry_run_export(self.store, label="structured-secret")

        encoded = json.dumps({"analysis": analysis, "item": item, "bundle": bundle})
        self.assertEqual(analysis["category"], "API-Keys")
        self.assertEqual(analysis["sensitivity"], "sensitive")
        self.assertIn("[REDACTED:secret]", analysis["preview"])
        self.assertNotIn("content", item)
        for raw in (
            "jsonSecretToken1234567890",
            "jsonBearerToken1234567890",
            "headerSecretToken1234567890",
            "querySecretToken1234567890",
        ):
            self.assertNotIn(raw, encoded)

    def test_schema_has_goal_entities(self):
        tables = set(self.store.table_names())

        self.assertGreaterEqual(
            tables,
            {
                "items",
                "receipts",
                "facets",
                "families",
                "links",
                "events",
                "summaries",
                "safe_exports",
                "shelves",
            },
        )

    def test_memory_summaries_create_redacted_recent_project_category_and_long_horizon_rollups(self):
        self.store.capture(
            "Prompt: summarize routing failures for the local proxy",
            source="manual",
            project="skratched",
            created_at="2026-06-18T08:00:00Z",
        )
        self.store.capture(
            "select id, email from users where active = true;",
            source="clipboard",
            project="crm",
            created_at="2026-06-18T08:05:00Z",
        )
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-summaryaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
            created_at="2026-06-18T08:10:00Z",
        )

        rollups = self.store.memory_summaries()
        encoded = json.dumps(rollups)
        by_kind_scope = {(entry["kind"], entry["scope_type"], entry["scope_value"]): entry for entry in rollups["summaries"]}
        stored_rollups = self.store.conn.execute(
            "SELECT kind, scope_type, scope_value, item_count, content_hash FROM summaries WHERE kind LIKE 'rollup:%'"
        ).fetchall()

        self.assertIn(("rollup:recent", "recent", "latest"), by_kind_scope)
        self.assertIn(("rollup:project", "project", "skratched"), by_kind_scope)
        self.assertIn(("rollup:category", "category", "API-Keys"), by_kind_scope)
        self.assertIn(("rollup:long_horizon", "long_horizon", "all"), by_kind_scope)
        self.assertEqual(by_kind_scope[("rollup:project", "project", "skratched")]["item_count"], 2)
        self.assertEqual(by_kind_scope[("rollup:category", "category", "API-Keys")]["item_count"], 1)
        self.assertTrue(all(len(row["content_hash"]) == 64 for row in stored_rollups))
        self.assertGreaterEqual(len(stored_rollups), 4)
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-summary", encoded)

    def test_capture_creates_item_receipt_event_and_duplicate_family(self):
        text = "select * from users where email = 'a@example.com';"

        first = self.store.capture(text, source="clipboard", project="crm")
        second = self.store.capture(text, source="clipboard", project="crm")

        self.assertEqual(first["content_hash"], second["content_hash"])
        self.assertEqual(first["family_id"], second["family_id"])
        self.assertEqual(self.store.count_rows("receipts"), 2)
        self.assertGreaterEqual(self.store.count_rows("events"), 2)
        self.assertEqual(first["category"], "SQL queries")

    def test_capture_lifecycle_events_include_redacted_timing_and_index_update(self):
        item = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-lifecycleaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
        )

        capture_event = self.store.events_for_item(item["id"], event_type="capture.created")[0]
        index_event = self.store.events_for_item(item["id"], event_type="index.updated")[0]
        encoded = json.dumps({"capture": capture_event, "index": index_event})

        self.assertEqual(capture_event["payload"]["lifecycle"], "capture")
        self.assertGreaterEqual(capture_event["payload"]["timing"]["total_ms"], 0)
        self.assertGreaterEqual(capture_event["payload"]["timing"]["analysis_ms"], 0)
        self.assertGreaterEqual(capture_event["payload"]["timing"]["index_ms"], 0)
        self.assertEqual(index_event["payload"]["lifecycle"], "index")
        self.assertEqual(index_event["payload"]["index"], "item_fts")
        self.assertEqual(index_event["payload"]["operation"], "upsert")
        self.assertEqual(index_event["payload"]["item_id"], item["id"])
        self.assertGreaterEqual(index_event["payload"]["timing"]["total_ms"], 0)
        self.assertIn("content", index_event["payload"]["indexed_fields"])
        self.assertNotIn("sk-or-v1-lifecycle", encoded)

    def test_search_lifecycle_event_includes_redacted_timing_diagnostics(self):
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-searchlifeaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
        )

        self.store.search("sk-or-v1-searchlifeaaaaaaaaaaaaaaaaaaaaaaaaaaa OpenRouter")
        event = self.store.events_for_item(None, event_type="search.executed")[-1]
        encoded = json.dumps(event)

        self.assertEqual(event["payload"]["lifecycle"], "search")
        self.assertGreaterEqual(event["payload"]["timing"]["total_ms"], 0)
        self.assertGreaterEqual(event["payload"]["timing"]["fts_ms"], 0)
        self.assertGreaterEqual(event["payload"]["timing"]["scoring_ms"], 0)
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-searchlife", encoded)

    def test_event_hash_chain_verifies_append_only_events(self):
        item = self.store.capture("hash chain note for event integrity", source="manual", project="audit")
        self.store.update_tags(item["id"], ["audit-chain"], reason="verify event chain")

        report = self.store.event_integrity_report()
        events = self.store.events_for_item(item["id"])

        self.assertTrue(report["ok"])
        self.assertGreaterEqual(report["events"], 2)
        self.assertEqual(report["verified_events"], report["events"])
        self.assertEqual(len(report["head_hash"]), 64)
        self.assertEqual(events[0]["previous_event_hash"], None)
        self.assertEqual(len(events[0]["event_hash"]), 64)
        self.assertEqual(events[1]["previous_event_hash"], events[0]["event_hash"])

    def test_event_hash_chain_detects_payload_tampering(self):
        item = self.store.capture("OPENROUTER_API_KEY=sk-or-v1-chainaaaaaaaaaaaaaaaaaaaaaaaaaaaa", source="clipboard")
        event = self.store.events_for_item(item["id"], event_type="capture.created")[0]
        self.store.conn.execute(
            "UPDATE events SET payload_json = ? WHERE id = ?",
            (json.dumps({"category": "notes", "raw": "sk-or-v1-chainaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}), event["id"]),
        )
        self.store.conn.commit()

        report = self.store.event_integrity_report()
        encoded = json.dumps(report)

        self.assertFalse(report["ok"])
        self.assertEqual(report["broken_event_id"], event["id"])
        self.assertEqual(report["failure"], "event_hash_mismatch")
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-chain", encoded)

    def test_capture_applies_valid_optional_ai_analysis_and_indexes_metadata(self):
        def fake_adapter(text, deterministic):
            return {
                "schema": "skratched.ai_analysis.v1",
                "category": "research",
                "summary": "Routing decision note",
                "tags": ["AI-Routing", "Follow Up"],
                "confidence": 0.91,
                "reason": "fake adapter found routing context",
            }

        item = self.store.capture(
            "Research note about choosing an OpenRouter model for local routing.",
            source="manual",
            project="skratched",
            ai_adapter=fake_adapter,
            ai_provider="fake-local",
        )
        results = self.store.search("ai-routing follow-up")
        events = self.store.events_for_item(item["id"], event_type="item.ai_analysis")

        self.assertEqual(item["category"], "research")
        self.assertEqual(item["facets"]["ai_status"], "applied")
        self.assertEqual(item["facets"]["ai_provider"], "fake-local")
        self.assertIn("ai-routing", item["tags"])
        self.assertTrue(results)
        self.assertEqual(results[0]["id"], item["id"])
        self.assertEqual(events[0]["payload"]["status"], "applied")

    def test_capture_falls_back_when_optional_ai_adapter_fails_without_secret_leakage(self):
        def failing_adapter(text, deterministic):
            raise ValueError("adapter saw sk-or-v1-aifailurecccccccccccccccccccccccccccc")

        item = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-aifailurecccccccccccccccccccccccccccc",
            source="clipboard",
            project="skratched",
            ai_adapter=failing_adapter,
            ai_provider="fake-local",
        )
        events = self.store.events_for_item(item["id"], event_type="item.ai_analysis")
        encoded = json.dumps({"item": item, "events": events})

        self.assertEqual(item["category"], "API-Keys")
        self.assertEqual(item["facets"]["ai_status"], "fallback")
        self.assertEqual(events[0]["payload"]["status"], "fallback")
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-aifailure", encoded)

    def test_risk_class_is_exposed_and_preserved_in_redacted_export(self):
        blocked = self.store.capture("rm -rf / --no-preserve-root", source="clipboard", project="ops")
        bundle = build_dry_run_export(self.store, label="risk-class")
        entry = next(item for item in bundle["items"] if item["id"] == blocked["id"])

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                report = import_redacted_bundle(restored, bundle)
                restored_item = restored.get_item(blocked["id"])
            finally:
                restored.close()

        self.assertEqual(blocked["risk_class"], "blocked")
        self.assertEqual(blocked["facets"]["risk_class"], "blocked")
        self.assertIn("destructive", " ".join(blocked["risk_reasons"]))
        self.assertEqual(entry["facets"]["risk_class"], "blocked")
        self.assertEqual(restored_item["risk_class"], "blocked")
        self.assertEqual(report["imported"], 1)

    def test_ensure_shelf_is_idempotent_and_visible_without_items(self):
        first = self.store.ensure_shelf("follow-up", reason="default quick pick")
        second = self.store.ensure_shelf(" follow-up ", reason="duplicate click")

        categories = {entry["category"]: entry["count"] for entry in self.store.categories()}

        self.assertEqual(first["category"], "follow-up")
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(categories["follow-up"], 0)
        self.assertEqual(self.store.count_rows("shelves"), 1)
        events = self.store.events_for_item(None, event_type="shelf.created")
        self.assertEqual(len(events), 1)

    def test_refile_to_new_category_creates_reusable_shelf(self):
        item = self.store.capture("Random note for triage", source="manual", project="desk")

        updated = self.store.refile_item(item["id"], "triage", reason="new shelf")
        again = self.store.ensure_shelf("triage", reason="reuse")

        categories = {entry["category"]: entry["count"] for entry in self.store.categories()}
        self.assertEqual(updated["category"], "triage")
        self.assertEqual(categories["triage"], 1)
        self.assertEqual(again["category"], "triage")
        self.assertEqual(self.store.count_rows("shelves"), 1)

    def test_capture_artifact_stores_screenshot_blob_metadata_and_receipt(self):
        payload = b"\x89PNG\r\n\x1a\nfake-screenshot-bytes"

        item = self.store.capture_artifact(
            filename="Screenshot 2026-06-18 at 10.00.00.png",
            content=payload,
            media_type="image/png",
            source="screenshot-work",
            project="skratched",
        )

        self.assertEqual(item["category"], "screenshots-work")
        self.assertEqual(item["facets"]["filename"], "Screenshot 2026-06-18 at 10.00.00.png")
        self.assertEqual(item["facets"]["media_type"], "image/png")
        self.assertEqual(item["facets"]["byte_size"], len(payload))
        self.assertTrue(item["facets"]["artifact_path"].startswith("artifacts/"))
        self.assertTrue((self.db_path.parent / item["facets"]["artifact_path"]).exists())
        self.assertEqual(self.store.count_rows("receipts"), 1)
        events = self.store.events_for_item(item["id"], event_type="capture.artifact_created")
        self.assertEqual(len(events), 1)
        self.assertNotIn("fake-screenshot-bytes", json.dumps(item))

    def test_duplicate_artifacts_share_content_hash_family_despite_different_names(self):
        payload = b"same-image-bytes"

        first = self.store.capture_artifact(
            filename="screenshot-a.png",
            content=payload,
            media_type="image/png",
            source="drop",
        )
        second = self.store.capture_artifact(
            filename="renamed-screenshot.png",
            content=payload,
            media_type="image/png",
            source="drop",
        )

        self.assertEqual(first["content_hash"], second["content_hash"])
        self.assertEqual(first["family_id"], second["family_id"])
        self.assertEqual(self.store.count_rows("artifacts"), 2)

    def test_scan_screenshot_watch_imports_new_images_and_skips_duplicates(self):
        watch_dir = Path(self.tmp.name) / "screenshots"
        watch_dir.mkdir()
        screenshot = watch_dir / "Screenshot 2026-06-18 at 12.34.56.png"
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\nwatch-screenshot")
        ignored = watch_dir / "notes.txt"
        ignored.write_text("not a screenshot")

        first = self.store.scan_screenshot_watch(watch_dir, project="skratched")
        second = self.store.scan_screenshot_watch(watch_dir, project="skratched")

        self.assertEqual(first["imported_count"], 1)
        self.assertEqual(first["skipped_count"], 0)
        self.assertEqual(first["items"][0]["category"], "screenshots-work")
        self.assertEqual(first["items"][0]["facets"]["source"], "screenshot-watch")
        self.assertEqual(first["items"][0]["facets"]["observed_path"], str(screenshot.resolve()))
        self.assertIn("mtime_ns", first["items"][0]["facets"]["stat_fingerprint"])
        self.assertEqual(second["imported_count"], 0)
        self.assertEqual(second["skipped_count"], 1)
        self.assertEqual(second["skipped"][0]["reason"], "duplicate_artifact_hash")
        self.assertEqual(self.store.count_rows("artifacts"), 1)
        events = self.store.events_for_item(first["items"][0]["id"], event_type="capture.screenshot_watch_imported")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["observed_path"], str(screenshot.resolve()))
        self.assertNotIn("watch-screenshot", json.dumps(first))

    def test_search_returns_openrouter_key_with_associated_context(self):
        note = self.store.capture("OpenRouter key used for local routing test", source="note", project="skratched")
        key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-cccccccccccccccccccccccccccccccccccccccccccccccc",
            source="clipboard",
            project="skratched",
        )
        self.store.link_items(key["id"], note["id"], "associated_context")

        results = self.store.search("last OpenRouter API keys added in the last 3 weeks", now="2026-06-18T12:00:00Z")

        self.assertTrue(results)
        top = results[0]
        self.assertEqual(top["id"], key["id"])
        self.assertEqual(top["category"], "API-Keys")
        self.assertIn("[REDACTED:openrouter_key]", top["preview"])
        self.assertNotIn("sk-or-v1-cccc", json.dumps(top))
        self.assertEqual(top["associated"][0]["id"], note["id"])
        self.assertIn("OpenRouter key used", top["associated"][0]["preview"])

    def test_time_window_recall_returns_recent_key_with_context_not_stale_key(self):
        old_key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr",
            source="clipboard",
            project="old-project",
            created_at="2026-05-01T12:00:00Z",
        )
        note = self.store.capture(
            "Recent OpenRouter key belongs with the local proxy config",
            source="note",
            project="skratched",
            created_at="2026-06-16T12:00:00Z",
        )
        recent_key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-ssssssssssssssssssssssssssssssssssssssssssssssss",
            source="clipboard",
            project="skratched",
            created_at="2026-06-17T12:00:00Z",
        )
        self.store.link_items(recent_key["id"], note["id"], "associated_context")

        results = self.store.search(
            "find my last OpenRouter API keys added in the last 3 weeks",
            now="2026-06-18T12:00:00Z",
        )

        result_ids = [item["id"] for item in results]
        self.assertEqual(results[0]["id"], recent_key["id"])
        self.assertNotIn(old_key["id"], result_ids)
        self.assertEqual(results[0]["associated"][0]["id"], note["id"])
        self.assertNotIn("sk-or-v1-ssss", json.dumps(results))
        self.assertNotIn("sk-or-v1-rrrr", json.dumps(results))

    def test_search_associated_context_includes_incoming_links(self):
        note = self.store.capture(
            "Proxy setup note explains where the OpenRouter key is used",
            source="note",
            project="skratched",
        )
        key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-tttttttttttttttttttttttttttttttttttttttttttttttt",
            source="clipboard",
            project="skratched",
        )
        self.store.link_items(note["id"], key["id"], "used_with")

        results = self.store.search("last OpenRouter API keys added in the last 3 weeks", now="2026-06-18T12:00:00Z")

        self.assertEqual(results[0]["id"], key["id"])
        self.assertEqual(results[0]["associated"][0]["id"], note["id"])
        self.assertEqual(results[0]["associated"][0]["link_type"], "used_with")
        self.assertNotIn("sk-or-v1-tttt", json.dumps(results))

    def test_search_associated_context_includes_neighboring_captures_without_links(self):
        before = self.store.capture(
            "Set up local proxy before adding the OpenRouter key",
            source="note",
            project="skratched",
            created_at="2026-06-18T09:00:00Z",
        )
        key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-neighborsearchaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
            created_at="2026-06-18T09:01:00Z",
        )
        after = self.store.capture(
            "Prompt: verify the local proxy after key rotation",
            source="manual",
            project="skratched",
            created_at="2026-06-18T09:02:00Z",
        )
        other_project = self.store.capture(
            "Unrelated project note should not be treated as neighboring context",
            source="manual",
            project="other",
            created_at="2026-06-18T09:01:30Z",
        )

        results = self.store.search("last OpenRouter API keys added in the last 3 weeks", now="2026-06-18T12:00:00Z")
        associated = results[0]["associated"]
        associated_by_type = {item["link_type"]: item for item in associated}
        encoded = json.dumps(results)

        self.assertEqual(results[0]["id"], key["id"])
        self.assertEqual(associated_by_type["previous_capture"]["id"], before["id"])
        self.assertEqual(associated_by_type["previous_capture"]["link_direction"], "chronological")
        self.assertEqual(associated_by_type["next_capture"]["id"], after["id"])
        self.assertNotIn(other_project["id"], {item["id"] for item in associated})
        self.assertNotIn("sk-or-v1-neighborsearch", encoded)

    def test_recall_top_result_is_stable_under_query_punctuation_and_case(self):
        key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu",
            source="clipboard",
            project="skratched",
            created_at="2026-06-18T10:00:00Z",
        )
        self.store.capture(
            "OpenRouter provider notes without a key value",
            source="note",
            project="skratched",
            created_at="2026-06-18T11:00:00Z",
        )

        plain = self.store.search("last OpenRouter API keys added in the last 3 weeks", now="2026-06-18T12:00:00Z")
        noisy = self.store.search("FIND: last OPENROUTER api-keys, added in last 3 weeks!!!", now="2026-06-18T12:00:00Z")

        self.assertEqual(plain[0]["id"], key["id"])
        self.assertEqual(noisy[0]["id"], key["id"])
        self.assertNotIn("sk-or-v1-uuuu", json.dumps({"plain": plain, "noisy": noisy}))

    def test_recent_key_recall_is_stable_across_time_window_phrasings(self):
        old_key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
            source="clipboard",
            project="old-project",
            created_at="2026-05-01T12:00:00Z",
        )
        recent_key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-yyyyyyyyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            source="clipboard",
            project="skratched",
            created_at="2026-06-17T12:00:00Z",
        )

        variants = [
            "find latest OpenRouter credential from past 21 days",
            "OPENROUTER token previous 21 days",
            "recent openrouter API key in three-week window",
        ]
        results_by_query = {
            query: self.store.search(query, now="2026-06-18T12:00:00Z")
            for query in variants
        }

        encoded = json.dumps(results_by_query)
        for query, results in results_by_query.items():
            self.assertTrue(results, query)
            self.assertEqual(results[0]["id"], recent_key["id"], query)
            self.assertNotIn(old_key["id"], [item["id"] for item in results], query)
        self.assertNotIn("sk-or-v1-yyyy", encoded)
        self.assertNotIn("sk-or-v1-xxxx", encoded)

    def test_local_semantic_search_finds_credential_intent_without_vector_db(self):
        note = self.store.capture(
            "This provider credential was copied while configuring the local model gateway.",
            source="note",
            project="skratched",
        )
        key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
            source="clipboard",
            project="skratched",
        )
        self.store.link_items(key["id"], note["id"], "associated_context")

        results = self.store.search(
            "provider credential token for model gateway last 3 weeks",
            now="2026-06-18T12:00:00Z",
        )

        self.assertTrue(results)
        top = results[0]
        self.assertEqual(top["id"], key["id"])
        self.assertGreater(top["scores"]["semantic"], 0)
        self.assertIn("local semantic", " ".join(top["why"]))
        self.assertEqual(top["associated"][0]["id"], note["id"])
        self.assertNotIn("sk-or-v1-hhhh", json.dumps(top))

    def test_semantic_signal_is_secondary_to_explicit_metadata(self):
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",
            source="clipboard",
            project="skratched",
        )
        sql = self.store.capture(
            "select id, email from users where active = true;",
            source="clipboard",
            project="crm",
        )

        results = self.store.search("SQL query users credential token")

        self.assertTrue(results)
        top = results[0]
        self.assertEqual(top["id"], sql["id"])
        self.assertEqual(top["category"], "SQL queries")
        self.assertGreater(top["scores"]["exact"], top["scores"]["semantic"])

    def test_search_supports_inline_category_project_and_tag_filters(self):
        wanted = self.store.capture(
            "Prompt: compare OpenRouter model routing options",
            source="manual",
            project="skratched",
        )
        self.store.update_tags(wanted["id"], ["Model Routing", "follow-up"], reason="filter fixture")
        self.store.capture(
            "Prompt: compare OpenRouter model routing options",
            source="manual",
            project="other",
        )
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-filteraaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
        )

        results = self.store.search("category:prompts project:skratched tag:model-routing OpenRouter")
        event = self.store.events_for_item(None, event_type="search.executed")[-1]
        encoded = json.dumps({"results": results, "event": event})

        self.assertEqual([item["id"] for item in results], [wanted["id"]])
        self.assertEqual(results[0]["filters"]["category"], "prompts")
        self.assertEqual(results[0]["filters"]["project"], "skratched")
        self.assertEqual(results[0]["filters"]["tag"], "model-routing")
        self.assertIn("filter category=prompts", results[0]["why"])
        self.assertEqual(event["payload"]["filters"]["category"], "prompts")
        self.assertNotIn("sk-or-v1-filter", encoded)

    def test_search_exposes_weighted_fts_signal_and_event_diagnostics(self):
        target = self.store.capture(
            "Prompt: troubleshoot local proxy timeout with routing trace",
            source="manual",
            project="skratched",
        )
        self.store.capture(
            "Prompt: unrelated timeout note for another project",
            source="manual",
            project="archive",
        )

        results = self.store.search("local proxy routing trace")
        event = self.store.events_for_item(None, event_type="search.executed")[-1]
        top = results[0]

        self.assertEqual(top["id"], target["id"])
        self.assertIn("fts", top["scores"])
        self.assertGreater(top["scores"]["fts"], 0)
        self.assertIn("FTS signal", " ".join(top["why"]))
        self.assertTrue(event["payload"]["fts"]["enabled"])
        self.assertGreaterEqual(event["payload"]["fts"]["matches"], 1)

    def test_search_fts_event_diagnostics_stay_redacted_for_secret_queries(self):
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-ftseventaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
        )

        self.store.search("sk-or-v1-ftseventaaaaaaaaaaaaaaaaaaaaaaaaaaaa OpenRouter")
        event = self.store.events_for_item(None, event_type="search.executed")[-1]
        encoded = json.dumps(event)

        self.assertTrue(event["payload"]["fts"]["enabled"])
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-ftsevent", encoded)

    def test_search_supports_shelf_alias_and_excludes_other_categories(self):
        sql = self.store.capture(
            "select id, email from users where active = true;",
            source="clipboard",
            project="crm",
        )
        self.store.capture(
            "Prompt: users table migration checklist",
            source="manual",
            project="crm",
        )

        results = self.store.search("shelf:SQL queries users")

        self.assertEqual([item["id"] for item in results], [sql["id"]])
        self.assertEqual(results[0]["filters"]["category"], "SQL queries")

    def test_sql_extracted_metadata_is_searchable(self):
        sql = self.store.capture(
            """
            INSERT INTO audit_log (user_id, action)
            SELECT id, 'login'
            FROM users
            WHERE active = true;
            """,
            source="clipboard",
            project="crm",
        )

        results = self.store.search("audit_log insert users")

        self.assertTrue(results)
        self.assertEqual(results[0]["id"], sql["id"])
        self.assertEqual(results[0]["facets"]["sql_operations"], ["insert", "select"])
        self.assertEqual(results[0]["facets"]["sql_tables"], ["audit_log", "users"])

    def test_code_extracted_metadata_is_searchable(self):
        item = self.store.capture(
            """
            from pathlib import Path

            class CaptureRouter:
                def route_screenshot(self, path):
                    return Path(path).name
            """,
            source="clipboard",
            project="skratched",
            path="capture_router.py",
        )

        results = self.store.search("CaptureRouter route_screenshot pathlib")

        self.assertTrue(results)
        self.assertEqual(results[0]["id"], item["id"])
        self.assertEqual(results[0]["facets"]["code_language"], "python")
        self.assertEqual(results[0]["facets"]["code_symbols"], ["CaptureRouter", "route_screenshot"])
        self.assertEqual(results[0]["facets"]["code_imports"], ["pathlib.Path"])

    def test_dry_run_export_is_redacted_and_hashes_entries(self):
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-dddddddddddddddddddddddddddddddddddddddddddddddd",
            source="clipboard",
            project="skratched",
        )

        bundle = build_dry_run_export(self.store, label="smoke")

        encoded = json.dumps(bundle)
        self.assertEqual(bundle["mode"], "dry-run")
        self.assertIn("bundle_hash", bundle)
        self.assertIn("items", bundle)
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-dddd", encoded)

    def test_export_entry_ids_are_stable_and_validated(self):
        item = self.store.capture("Prompt: stable export entry id check", source="manual", project="skratched")

        first = build_dry_run_export(self.store, label="stable-one")
        second = build_dry_run_export(self.store, label="stable-two")
        entry = first["items"][0]
        parsed_jsonl = parse_jsonl_export(build_jsonl_export(self.store, label="stable-jsonl"))
        preview_store = SkratchedStore(Path(self.tmp.name) / "preview.db")
        try:
            preview = preview_redacted_bundle(preview_store, first)
        finally:
            preview_store.close()

        tampered = json.loads(json.dumps(first))
        tampered["items"][0]["entry_id"] = "export_entry_tampered"
        tampered.pop("bundle_hash")
        tampered["bundle_hash"] = __import__("hashlib").sha256(
            json.dumps(tampered, sort_keys=True).encode("utf-8")
        ).hexdigest()

        self.assertTrue(entry["entry_id"].startswith("export_entry_"))
        self.assertEqual(len(entry["entry_id"]), len("export_entry_") + 16)
        self.assertEqual(entry["entry_id"], second["items"][0]["entry_id"])
        self.assertEqual(entry["entry_id"], parsed_jsonl["items"][0]["entry_id"])
        self.assertEqual(preview["entries"][0]["entry_id"], entry["entry_id"])
        self.assertEqual(preview["entries"][0]["item_id"], item["id"])
        with self.assertRaisesRegex(ValueError, "entry_id mismatch"):
            preview_redacted_bundle(self.store, tampered)

    def test_jsonl_export_roundtrips_redacted_bundle_with_manifest_hash(self):
        source = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-jsonljsonljsonljsonljsonljsonljsonljsonljsonl",
            source="clipboard",
            project="skratched",
        )

        jsonl = build_jsonl_export(self.store, label="jsonl-smoke")
        parsed = parse_jsonl_export(jsonl)

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                preview = preview_redacted_jsonl(restored, jsonl)
                report = import_redacted_jsonl(restored, jsonl)
                restored_item = restored.get_item(source["id"])
            finally:
                restored.close()

        encoded = json.dumps({"jsonl": jsonl, "parsed": parsed, "preview": preview, "report": report, "restored": restored_item})
        lines = jsonl.splitlines()
        header = json.loads(lines[0])
        item_record = json.loads(lines[1])
        footer = json.loads(lines[-1])
        self.assertEqual(header["record_type"], "manifest")
        self.assertEqual(header["schema"], "skratched.export_jsonl.v1")
        self.assertEqual(item_record["record_type"], "item")
        self.assertEqual(item_record["entry_id"], parsed["items"][0]["entry_id"])
        self.assertEqual(footer["record_type"], "footer")
        self.assertEqual(parsed["schema"], "skratched.export.v1")
        self.assertEqual(parsed["bundle_hash"], footer["bundle_hash"])
        self.assertEqual(preview["importable_count"], 1)
        self.assertEqual(report["imported"], 1)
        self.assertEqual(restored_item["content_hash"], source["content_hash"])
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-jsonl", encoded)

    def test_jsonl_export_file_write_is_atomic_private_and_redacted(self):
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-fileexportaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
        )

        report = write_jsonl_export_file(self.store, label="backup sk-or-v1-fileexportaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        path = Path(report["path"])
        parsed = parse_jsonl_export(path.read_text())
        encoded = json.dumps({"report": report, "jsonl": path.read_text()})
        events = self.store.events_for_item(None, event_type="export.file_written")
        temp_files = list(path.parent.glob(f"{path.name}.*.tmp"))

        self.assertEqual(report["schema"], "skratched.export_file.v1")
        self.assertEqual(report["format"], "jsonl")
        self.assertEqual(path.parent.resolve(), (self.store.db_path.parent / "exports").resolve())
        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(parsed["bundle_hash"], report["bundle_hash"])
        self.assertEqual(parsed["item_count"], report["item_count"])
        self.assertEqual(report["bytes"], path.stat().st_size)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["bundle_hash"], report["bundle_hash"])
        self.assertEqual(events[0]["payload"]["path"], str(path))
        self.assertEqual(temp_files, [])
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-fileexport", encoded)

    def test_jsonl_import_rejects_tampered_item_line(self):
        self.store.capture("Prompt: JSONL tamper check", source="manual", project="skratched")
        jsonl = build_jsonl_export(self.store, label="jsonl-tamper")
        lines = jsonl.splitlines()
        item = json.loads(lines[1])
        item["item"]["preview"] = "tampered preview"
        lines[1] = json.dumps(item, sort_keys=True)
        tampered = "\n".join(lines) + "\n"

        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            parse_jsonl_export(tampered)

    def test_generic_secret_capture_is_redacted_in_item_and_export_payloads(self):
        item = self.store.capture(
            """
            DATABASE_URL=postgresql://app_user:dbSecretPass123@db.local:5432/app
            curl -H "Authorization: Bearer bearer_secret_token_1234567890abcdef" https://example.test
            """,
            source="clipboard",
            project="skratched",
        )

        bundle = build_dry_run_export(self.store, label="generic-secret")
        encoded = json.dumps({"item": item, "bundle": bundle})
        self.assertEqual(item["category"], "API-Keys")
        self.assertEqual(item["sensitivity"], "sensitive")
        self.assertNotIn("content", item)
        self.assertIn("[REDACTED:credentials]", encoded)
        self.assertIn("[REDACTED:bearer_token]", encoded)
        self.assertNotIn("dbSecretPass123", encoded)
        self.assertNotIn("bearer_secret_token", encoded)

    def test_url_reference_metadata_roundtrips_export_and_search(self):
        raw_secret = "querySecretToken1234567890"
        source = self.store.capture(
            f"Reference docs: https://docs.example.test/guide?api_key={raw_secret}&page=1",
            source="clipboard",
            project="skratched",
        )
        bundle = build_dry_run_export(self.store, label="url-reference")
        entry = next(item for item in bundle["items"] if item["id"] == source["id"])

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                report = import_redacted_bundle(restored, bundle)
                results = restored.search("docs.example.test guide")
                restored_item = restored.get_item(source["id"])
            finally:
                restored.close()

        encoded = json.dumps({"bundle": bundle, "results": results, "restored": restored_item})
        refs = entry["facets"]["references"]
        self.assertEqual(report["imported"], 1)
        self.assertEqual(len(refs), 1)
        self.assertTrue(refs[0]["id"].startswith("ref_"))
        self.assertEqual(refs[0]["host"], "docs.example.test")
        self.assertIn("[REDACTED:secret]", refs[0]["url"])
        self.assertTrue(results)
        self.assertEqual(results[0]["id"], source["id"])
        self.assertEqual(restored_item["facets"]["references"], refs)
        self.assertNotIn(raw_secret, encoded)

    def test_dry_run_export_includes_safe_chunk_manifest_without_chunk_text(self):
        long_text = (
            "Project memory line with OpenRouter placeholder <OPENROUTER_API_KEY>.\n"
            + "alpha beta gamma delta " * 280
            + "tail marker for chunk export"
        )
        source = self.store.capture(long_text, source="manual", project="skratched")

        bundle = build_dry_run_export(self.store, label="chunk-manifest")

        entry = next(item for item in bundle["items"] if item["id"] == source["id"])
        chunks = entry["chunk_manifest"]
        encoded = json.dumps(bundle)
        self.assertGreater(len(chunks), 1)
        self.assertEqual(entry["facets"]["chunk_count"], len(chunks))
        self.assertEqual(chunks[0]["index"], 0)
        self.assertEqual(chunks[0]["start"], 0)
        self.assertEqual(chunks[1]["overlap_before"], 400)
        self.assertEqual(chunks[0]["length"], chunks[0]["end"] - chunks[0]["start"])
        self.assertEqual(len(chunks[0]["hash"]), 64)
        self.assertNotIn("text", chunks[0])
        self.assertNotIn("tail marker", encoded)

    def test_redacted_import_restores_safe_chunk_manifest_metadata(self):
        long_text = "Long prompt note\n" + ("section body " * 450) + "RESTORE_LATE_MARKER"
        source = self.store.capture(long_text, source="manual", project="skratched")
        bundle = build_dry_run_export(self.store, label="chunk-roundtrip")
        source_entry = next(item for item in bundle["items"] if item["id"] == source["id"])

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                report = import_redacted_bundle(restored, bundle)
                restored_item = restored.get_item(source["id"])
            finally:
                restored.close()

        encoded = json.dumps(restored_item)
        self.assertEqual(report["imported"], 1)
        self.assertEqual(restored_item["content_hash"], source["content_hash"])
        self.assertEqual(restored_item["facets"]["chunk_count"], len(source_entry["chunk_manifest"]))
        self.assertEqual(restored_item["chunks"], source_entry["chunk_manifest"])
        self.assertNotIn("RESTORE_LATE_MARKER", encoded)

    def test_import_preview_rejects_inconsistent_chunk_manifest_even_with_recomputed_bundle_hash(self):
        self.store.capture("Long note\n" + ("chunk parity " * 450), source="manual", project="skratched")
        bundle = build_dry_run_export(self.store, label="bad-chunk")
        tampered = json.loads(json.dumps(bundle))
        tampered["items"][0]["chunk_manifest"][0]["length"] += 1
        tampered.pop("bundle_hash")
        tampered["bundle_hash"] = __import__("hashlib").sha256(
            json.dumps(tampered, sort_keys=True).encode("utf-8")
        ).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                with self.assertRaisesRegex(ValueError, "chunk_manifest"):
                    preview_redacted_bundle(restored, tampered)
            finally:
                restored.close()

    def test_sensitive_item_requires_explicit_local_unlock_to_reveal(self):
        item = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-ffffffffffffffffffffffffffffffffffffffffffffffff",
            source="clipboard",
            project="skratched",
        )

        with self.assertRaises(PermissionError):
            self.store.reveal_item(item["id"], local_unlock=False, reason="accidental click")

        revealed = self.store.reveal_item(item["id"], local_unlock=True, reason="copy for local config")

        self.assertIn("sk-or-v1-ffffffff", revealed["content"])
        self.assertEqual(revealed["sensitivity"], "sensitive")
        events = self.store.events_for_item(item["id"], event_type="item.revealed")
        self.assertEqual(len(events), 1)
        self.assertNotIn("sk-or-v1-ffffffff", json.dumps(events))
        self.assertIn("copy for local config", events[0]["payload"]["reason"])

    def test_event_payloads_redact_secret_queries_and_reasons(self):
        item = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-ssssssssssssssssssssssssssssssssssssssssssssssss",
            source="clipboard",
            project="skratched",
        )
        raw_query_secret = "sk-or-v1-rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"
        raw_reason_secret = "reasonSecretToken1234567890"

        self.store.search(f"find credential {raw_query_secret}")
        with self.assertRaises(PermissionError):
            self.store.reveal_item(
                item["id"],
                local_unlock=False,
                reason=f'blocked reveal with {{"api_key": "{raw_reason_secret}"}}',
            )
        self.store.update_tags(
            item["id"],
            ["safe-log"],
            reason=f"tagging after Authorization: Bearer {raw_reason_secret}",
        )

        search_events = self.store.events_for_item(None, event_type="search.executed")
        item_events = self.store.events_for_item(item["id"])
        encoded = json.dumps({"search": search_events, "item": item_events})

        self.assertNotIn(raw_query_secret, encoded)
        self.assertNotIn(raw_reason_secret, encoded)
        self.assertIn("[REDACTED:openrouter_key]", search_events[-1]["payload"]["query"])
        self.assertIn("[REDACTED:secret]", encoded)

    def test_redacted_export_bundle_import_restores_metadata_without_secrets(self):
        source = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-gggggggggggggggggggggggggggggggggggggggggggggggg",
            source="clipboard",
            project="skratched",
        )
        bundle = build_dry_run_export(self.store, label="roundtrip")

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                report = import_redacted_bundle(restored, bundle)
                items = restored.list_items()
            finally:
                restored.close()

        encoded = json.dumps(items)
        self.assertEqual(report["imported"], 1)
        self.assertEqual(items[0]["content_hash"], source["content_hash"])
        self.assertEqual(items[0]["category"], "API-Keys")
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-gggg", encoded)

    def test_import_preview_marks_existing_duplicates_and_apply_skips_them(self):
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj",
            source="clipboard",
            project="skratched",
        )
        bundle = build_dry_run_export(self.store, label="same-store")

        preview = preview_redacted_bundle(self.store, bundle)
        report = import_redacted_bundle(self.store, bundle)

        encoded = json.dumps({"preview": preview, "report": report})
        self.assertEqual(preview["item_count"], 1)
        self.assertEqual(preview["importable_count"], 0)
        self.assertEqual(preview["duplicate_count"], 1)
        self.assertEqual(preview["entries"][0]["action"], "skip_existing_duplicate")
        self.assertEqual(report["imported"], 0)
        self.assertEqual(report["skipped"], 1)
        self.assertEqual(self.store.count_rows("items"), 1)
        self.assertNotIn("sk-or-v1-jjjj", encoded)

    def test_import_preview_marks_duplicate_entries_inside_bundle(self):
        text = "select * from users where email = 'duplicate@example.com';"
        self.store.capture(text, source="clipboard", project="crm")
        self.store.capture(text, source="clipboard", project="crm")
        bundle = build_dry_run_export(self.store, label="duplicate-bundle")

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                preview = preview_redacted_bundle(restored, bundle)
                report = import_redacted_bundle(restored, bundle)
                rows = restored.list_items()
            finally:
                restored.close()

        self.assertEqual(preview["item_count"], 2)
        self.assertEqual(preview["importable_count"], 1)
        self.assertEqual(preview["duplicate_count"], 1)
        self.assertEqual([entry["action"] for entry in preview["entries"]], ["import", "skip_bundle_duplicate"])
        self.assertEqual(report["imported"], 1)
        self.assertEqual(report["skipped"], 1)
        self.assertEqual(len(rows), 1)

    def test_redacted_import_preserves_structured_sql_metadata_for_search(self):
        source = self.store.capture(
            """
            INSERT INTO audit_log (user_id, action)
            SELECT id, 'login'
            FROM users
            WHERE active = true;
            """,
            source="clipboard",
            project="crm",
        )
        bundle = build_dry_run_export(self.store, label="sql-metadata-roundtrip")

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                report = import_redacted_bundle(restored, bundle)
                results = restored.search("audit_log insert users")
            finally:
                restored.close()

        self.assertEqual(report["imported"], 1)
        self.assertTrue(results)
        self.assertEqual(results[0]["content_hash"], source["content_hash"])
        self.assertEqual(results[0]["facets"]["sql_operations"], ["insert", "select"])
        self.assertEqual(results[0]["facets"]["sql_tables"], ["audit_log", "users"])
        self.assertEqual(results[0]["source"], "safe_import")

    def test_redacted_import_restores_tag_facets_into_search_and_counts(self):
        item = self.store.capture("Prompt: compare model routing options", source="manual", project="skratched")
        self.store.update_tags(item["id"], ["model-routing", "follow-up"], reason="roundtrip tags")
        bundle = build_dry_run_export(self.store, label="tag-roundtrip")

        with tempfile.TemporaryDirectory() as tmp:
            restored = SkratchedStore(Path(tmp) / "restore.db")
            try:
                report = import_redacted_bundle(restored, bundle)
                tags = restored.tags()
                results = restored.search("model-routing follow-up")
            finally:
                restored.close()

        tag_counts = {entry["tag"]: entry["count"] for entry in tags}
        self.assertEqual(report["imported"], 1)
        self.assertEqual(tag_counts["model-routing"], 1)
        self.assertEqual(tag_counts["follow-up"], 1)
        self.assertTrue(results)
        self.assertEqual(results[0]["content_hash"], item["content_hash"])
        self.assertEqual(results[0]["facets"]["tags"], ["model-routing", "follow-up"])

    def test_context_graph_includes_associated_and_duplicate_family_edges(self):
        first = self.store.capture("select * from users where id = 1;", source="clipboard", project="crm")
        duplicate = self.store.capture("select * from users where id = 1;", source="clipboard", project="crm")
        note = self.store.capture("This query is used by the customer lookup panel", source="note", project="crm")
        self.store.link_items(first["id"], note["id"], "used_with")

        graph = self.store.context_graph(first["id"])

        node_ids = {node["id"] for node in graph["nodes"]}
        edge_types = {(edge["from"], edge["to"], edge["type"]) for edge in graph["edges"]}
        self.assertEqual(graph["root"]["id"], first["id"])
        self.assertIn(duplicate["id"], node_ids)
        self.assertIn(note["id"], node_ids)
        self.assertIn((first["id"], note["id"], "used_with"), edge_types)
        self.assertIn((first["id"], duplicate["id"], "same_content_family"), edge_types)

    def test_context_graph_includes_neighboring_capture_edges(self):
        before = self.store.capture(
            "Note before the local proxy key capture",
            source="note",
            project="skratched",
            created_at="2026-06-18T08:00:00Z",
        )
        key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-neighborgraphaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="skratched",
            created_at="2026-06-18T08:01:00Z",
        )
        after = self.store.capture(
            "Prompt: check routing after the proxy key capture",
            source="manual",
            project="skratched",
            created_at="2026-06-18T08:02:00Z",
        )

        graph = self.store.context_graph(key["id"])
        node_ids = {node["id"] for node in graph["nodes"]}
        edge_types = {(edge["from"], edge["to"], edge["type"]) for edge in graph["edges"]}
        cluster_by_name = {cluster["name"]: cluster for cluster in graph["clusters"]}
        encoded = json.dumps(graph)

        self.assertIn(before["id"], node_ids)
        self.assertIn(after["id"], node_ids)
        self.assertIn((key["id"], before["id"], "previous_capture"), edge_types)
        self.assertIn((key["id"], after["id"], "next_capture"), edge_types)
        self.assertIn(before["id"], cluster_by_name["chronological neighbors"]["item_ids"])
        self.assertIn(after["id"], cluster_by_name["chronological neighbors"]["item_ids"])
        self.assertNotIn("sk-or-v1-neighborgraph", encoded)

    def test_near_duplicate_prompt_revision_links_without_collapsing_exact_family(self):
        first = self.store.capture(
            "Prompt: summarize the release notes with risks, citations, and next actions.",
            source="manual",
            project="docs",
        )
        revised = self.store.capture(
            "Prompt - summarize release notes with citations, risks, and concrete next actions for review.",
            source="manual",
            project="docs",
        )

        graph = self.store.context_graph(revised["id"])

        near_edges = [edge for edge in graph["edges"] if edge["type"] == "near_duplicate"]
        cluster_by_name = {cluster["name"]: cluster for cluster in graph["clusters"]}
        revised = self.store.get_item(revised["id"])
        self.assertNotEqual(first["content_hash"], revised["content_hash"])
        self.assertNotEqual(first["family_id"], revised["family_id"])
        self.assertEqual(len(near_edges), 1)
        self.assertEqual(near_edges[0]["from"], revised["id"])
        self.assertEqual(near_edges[0]["to"], first["id"])
        self.assertEqual(cluster_by_name["near duplicates"]["item_ids"], [first["id"]])
        self.assertEqual(revised["facets"]["near_duplicate_of"], first["id"])
        self.assertGreaterEqual(float(revised["facets"]["near_duplicate_score"]), 0.72)
        self.assertTrue(any("near-duplicate" in hint for hint in graph["memory_hints"]))

    def test_near_duplicate_detection_ignores_unrelated_captures(self):
        first = self.store.capture("Prompt: summarize release notes with citations.", source="manual", project="docs")
        other = self.store.capture("select id, email from users where active = true;", source="clipboard", project="crm")

        graph = self.store.context_graph(other["id"])

        self.assertNotIn("near_duplicate_of", self.store.get_item(other["id"])["facets"])
        self.assertNotIn(first["id"], {node["id"] for node in graph["nodes"]})
        self.assertNotIn("near_duplicate", {edge["type"] for edge in graph["edges"]})

    def test_near_duplicate_secret_events_and_context_stay_redacted(self):
        first = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="keys",
        )
        revised = self.store.capture(
            "export OPENROUTER_API_KEY=sk-or-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            source="clipboard",
            project="keys",
        )

        graph = self.store.context_graph(revised["id"])
        events = self.store.events_for_item(revised["id"], event_type="item.near_duplicate_detected")
        encoded = json.dumps({"graph": graph, "events": events, "item": self.store.get_item(revised["id"])})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["existing_item_id"], first["id"])
        self.assertNotIn("sk-or-v1-aaaa", encoded)
        self.assertNotIn("sk-or-v1-bbbb", encoded)

    def test_context_graph_adds_memory_map_summary_and_clusters(self):
        root = self.store.capture("OPENROUTER_API_KEY=sk-or-v1-llllllllllllllllllllllllllllllllllllllllllllllll", source="clipboard", project="skratched")
        note = self.store.capture("OpenRouter key belongs with the local proxy config", source="note", project="skratched")
        prompt = self.store.capture("Prompt: test OpenRouter routing after config changes", source="manual", project="skratched")
        duplicate = self.store.capture("OPENROUTER_API_KEY=sk-or-v1-llllllllllllllllllllllllllllllllllllllllllllllll", source="clipboard", project="skratched")
        successor = self.store.capture("OPENROUTER_API_KEY=<OPENROUTER_API_KEY> for local proxy placeholder", source="manual", project="skratched")
        self.store.link_items(root["id"], note["id"], "used_with")
        self.store.link_items(root["id"], prompt["id"], "follow_up_to")
        self.store.mark_replacement(root["id"], successor["id"], reason="replace raw key with placeholder")

        graph = self.store.context_graph(root["id"])

        self.assertEqual(graph["summary"]["node_count"], 5)
        self.assertEqual(graph["summary"]["edge_count"], 4)
        self.assertEqual(graph["summary"]["root_category"], "API-Keys")
        self.assertEqual(graph["summary"]["edge_types"]["used_with"], 1)
        self.assertEqual(graph["summary"]["edge_types"]["follow_up_to"], 1)
        self.assertEqual(graph["summary"]["edge_types"]["same_content_family"], 1)
        self.assertEqual(graph["summary"]["edge_types"]["replaced_by"], 1)
        self.assertIn("API-Keys", graph["summary"]["categories"])
        cluster_by_name = {cluster["name"]: cluster for cluster in graph["clusters"]}
        self.assertEqual(cluster_by_name["linked context"]["count"], 2)
        self.assertIn(note["id"], cluster_by_name["linked context"]["item_ids"])
        self.assertIn(prompt["id"], cluster_by_name["linked context"]["item_ids"])
        self.assertEqual(cluster_by_name["duplicates"]["item_ids"], [duplicate["id"]])
        self.assertEqual(cluster_by_name["replacement path"]["item_ids"], [successor["id"]])
        self.assertTrue(any("linked context" in hint for hint in graph["memory_hints"]))
        self.assertNotIn("sk-or-v1-llllllll", json.dumps(graph))

    def test_likely_next_suggestions_surface_context_without_secret_leakage(self):
        key = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-nextnextnextnextnextnextnextnextnextnextnextnext",
            source="clipboard",
            project="skratched",
        )
        note = self.store.capture("OpenRouter key belongs with the local proxy config", source="note", project="skratched")
        screenshot = self.store.capture_artifact(
            filename="Screenshot OpenRouter settings.png",
            content=b"\x89PNG\r\n\x1a\nnext-screenshot",
            media_type="image/png",
            source="screenshot-work",
            project="skratched",
        )
        self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-nextnextnextnextnextnextnextnextnextnextnextnext",
            source="clipboard",
            project="skratched",
        )
        self.store.link_items(key["id"], note["id"], "used_with")
        self.store.link_items(key["id"], screenshot["id"], "screenshot_of")

        item = self.store.get_item(key["id"])
        results = self.store.search("OpenRouter credential last 3 weeks")
        suggestion_types = {suggestion["type"] for suggestion in item["next_suggestions"]}
        search_suggestion_types = {suggestion["type"] for suggestion in results[0]["next_suggestions"]}
        encoded = json.dumps({"item": item, "results": results})

        self.assertIn("open_project_shelf", suggestion_types)
        self.assertIn("search_vendor_context", suggestion_types)
        self.assertIn("review_duplicate_family", suggestion_types)
        self.assertIn("open_linked_context", suggestion_types)
        self.assertIn("open_associated_screenshot", suggestion_types)
        self.assertIn("search_vendor_context", search_suggestion_types)
        self.assertNotIn("sk-or-v1-next", encoded)
        self.assertNotIn("next-screenshot", encoded)

    def test_likely_next_suggestions_point_deprecated_items_to_successor(self):
        old = self.store.capture("Prompt v1: summarize notes quickly", source="manual", project="prompts")
        new = self.store.capture("Prompt v2: summarize notes with citations", source="manual", project="prompts")
        self.store.mark_replacement(old["id"], new["id"], reason="newer prompt adds citations")

        item = self.store.get_item(old["id"])
        replacement_suggestions = [suggestion for suggestion in item["next_suggestions"] if suggestion["type"] == "use_successor"]

        self.assertEqual(len(replacement_suggestions), 1)
        self.assertEqual(replacement_suggestions[0]["item_id"], new["id"])
        self.assertIn("newer prompt", replacement_suggestions[0]["reason"])

    def test_context_graph_includes_bounded_second_hop_context_trail(self):
        root = self.store.capture("OPENROUTER_API_KEY=sk-or-v1-wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww", source="clipboard", project="skratched")
        note = self.store.capture("OpenRouter proxy config note", source="note", project="skratched")
        screenshot = self.store.capture("Screenshot shows the model gateway settings page", source="manual", project="skratched")
        unrelated = self.store.capture("Unrelated meeting note", source="manual", project="skratched")
        self.store.link_items(root["id"], note["id"], "used_with")
        self.store.link_items(note["id"], screenshot["id"], "screenshot_of")
        self.store.link_items(screenshot["id"], unrelated["id"], "follow_up_to")

        graph = self.store.context_graph(root["id"])

        node_ids = {node["id"] for node in graph["nodes"]}
        nodes_by_id = {node["id"]: node for node in graph["nodes"]}
        edge_types = {(edge["from"], edge["to"], edge["type"], edge["depth"]) for edge in graph["edges"]}
        cluster_by_name = {cluster["name"]: cluster for cluster in graph["clusters"]}
        self.assertIn(note["id"], node_ids)
        self.assertIn(screenshot["id"], node_ids)
        self.assertNotIn(unrelated["id"], node_ids)
        self.assertEqual(nodes_by_id[root["id"]]["graph_depth"], 0)
        self.assertEqual(nodes_by_id[note["id"]]["graph_depth"], 1)
        self.assertEqual(nodes_by_id[screenshot["id"]]["graph_depth"], 2)
        self.assertIn((root["id"], note["id"], "used_with", 1), edge_types)
        self.assertIn((note["id"], screenshot["id"], "screenshot_of", 2), edge_types)
        self.assertIn(screenshot["id"], cluster_by_name["linked context"]["item_ids"])
        self.assertTrue(any("2-hop" in hint for hint in graph["memory_hints"]))
        self.assertNotIn("sk-or-v1-wwww", json.dumps(graph))

    def test_replacement_marks_old_item_deprecated_and_points_to_successor(self):
        old = self.store.capture("Prompt v1: summarize notes quickly", source="manual", project="prompts")
        new = self.store.capture("Prompt v2: summarize notes with citations and risks", source="manual", project="prompts")

        self.store.mark_replacement(old["id"], new["id"], reason="newer prompt preserves citations")
        graph = self.store.context_graph(old["id"])

        self.assertTrue(graph["root"]["deprecated"])
        self.assertEqual(graph["root"]["successor_id"], new["id"])
        replacement_edges = [edge for edge in graph["edges"] if edge["type"] == "replaced_by"]
        self.assertEqual(len(replacement_edges), 1)
        self.assertEqual(replacement_edges[0]["from"], old["id"])
        self.assertEqual(replacement_edges[0]["to"], new["id"])
        events = self.store.events_for_item(old["id"], event_type="item.deprecated")
        self.assertEqual(len(events), 1)
        self.assertIn("newer prompt", events[0]["payload"]["reason"])

    def test_list_items_and_search_surface_deprecated_replacement_warning(self):
        old = self.store.capture("Prompt v1: summarize notes quickly", source="manual", project="prompts")
        new = self.store.capture("Prompt v2: summarize notes with citations and risks", source="manual", project="prompts")

        self.store.mark_replacement(old["id"], new["id"], reason="newer prompt preserves citations")
        listed_old = next(item for item in self.store.list_items() if item["id"] == old["id"])
        search_old = next(item for item in self.store.search("Prompt v1 summarize notes") if item["id"] == old["id"])

        self.assertTrue(listed_old["deprecated"])
        self.assertEqual(listed_old["successor_id"], new["id"])
        self.assertIn("newer prompt", listed_old["replacement_reason"])
        self.assertTrue(search_old["deprecated"])
        self.assertEqual(search_old["successor"]["id"], new["id"])
        self.assertIn("deprecated", " ".join(search_old["why"]).lower())

    def test_replacement_browser_lists_old_and_successor_items(self):
        old = self.store.capture("SQL v1: select * from users;", source="manual", project="crm")
        new = self.store.capture("SQL v2: select id, email from users where active = true;", source="manual", project="crm")

        self.store.mark_replacement(old["id"], new["id"], reason="narrower safer active-user query")
        replacements = self.store.list_replacements()

        self.assertEqual(len(replacements), 1)
        row = replacements[0]
        self.assertEqual(row["old"]["id"], old["id"])
        self.assertEqual(row["new"]["id"], new["id"])
        self.assertEqual(row["relation"], "replaced_by")
        self.assertIn("active-user", row["reason"])

    def test_action_safety_flow_blocks_destructive_command_without_leaking_reason(self):
        item = self.store.capture("rm -rf / --no-preserve-root", source="clipboard", project="ops")

        proposed = self.store.propose_item_action(item["id"], action="reuse")
        checked = self.store.check_item_action(item["id"], action="reuse")
        with self.assertRaisesRegex(PermissionError, "blocked"):
            self.store.apply_item_action(
                item["id"],
                action="reuse",
                approved=True,
                reason="approve sk-or-v1-actionblockedaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        events = self.store.events_for_item(item["id"])
        encoded = json.dumps({"proposed": proposed, "checked": checked, "events": events})

        self.assertEqual(proposed["schema"], "skratched.action_card.v1")
        self.assertEqual(proposed["risk_class"], "blocked")
        self.assertFalse(proposed["apply_allowed"])
        self.assertTrue(proposed["requires_approval"])
        self.assertEqual(checked["status"], "checked")
        self.assertEqual(checked["decision"], "blocked")
        self.assertTrue(any(event["event_type"] == "action.proposed" for event in events))
        self.assertTrue(any(event["event_type"] == "action.checked" for event in events))
        self.assertFalse(any(event["event_type"] == "action.applied" for event in events))
        self.assertNotIn("sk-or-v1-actionblocked", encoded)

    def test_action_safety_apply_records_approval_for_caution_item(self):
        item = self.store.capture("select id, email from users where active = true;", source="clipboard", project="crm")

        proposed = self.store.propose_item_action(item["id"], action="reuse")
        with self.assertRaisesRegex(PermissionError, "approval"):
            self.store.apply_item_action(item["id"], action="reuse", approved=False, reason="not approved")
        applied = self.store.apply_item_action(
            item["id"],
            action="reuse",
            approved=True,
            reason="approved for readonly review",
        )
        events = self.store.events_for_item(item["id"], event_type="action.applied")

        self.assertEqual(proposed["risk_class"], "caution")
        self.assertTrue(proposed["requires_approval"])
        self.assertTrue(proposed["apply_allowed"])
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(applied["decision"], "approved")
        self.assertTrue(applied["reversible"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["action_id"], applied["action_id"])

    def test_edit_item_creates_redacted_version_successor_history(self):
        old = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-versionoldaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="routing",
        )

        new = self.store.edit_item(
            old["id"],
            "OPENROUTER_API_KEY=<OPENROUTER_API_KEY> for routing placeholder",
            reason="replace sk-or-v1-versionoldaaaaaaaaaaaaaaaaaaaaaaaaaaaa with placeholder",
        )
        history = self.store.version_history(old["id"])
        graph = self.store.context_graph(old["id"])
        events = self.store.events_for_item(old["id"], event_type="item.edited")
        encoded = json.dumps({"new": new, "history": history, "graph": graph, "events": events})

        self.assertEqual(new["project"], "routing")
        self.assertEqual(history["root_item_id"], old["id"])
        self.assertEqual(history["latest_item_id"], new["id"])
        self.assertEqual([edge["relation"] for edge in history["edges"]], ["edited_to"])
        self.assertEqual(history["edges"][0]["old_item_id"], old["id"])
        self.assertEqual(history["edges"][0]["new_item_id"], new["id"])
        self.assertEqual([entry["id"] for entry in history["items"]], [old["id"], new["id"]])
        self.assertTrue(graph["root"]["deprecated"])
        self.assertEqual(graph["root"]["successor_id"], new["id"])
        self.assertEqual([edge["type"] for edge in graph["edges"] if edge["to"] == new["id"]], ["edited_to"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["successor_id"], new["id"])
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-versionold", encoded)

    def test_manual_refile_updates_category_index_and_audit_event(self):
        item = self.store.capture("select * from users where active = true;", source="clipboard", project="crm")

        updated = self.store.refile_item(item["id"], "research", reason="belongs with customer research")
        results = self.store.search("research customer")

        self.assertEqual(updated["category"], "research")
        self.assertTrue(updated["facets"]["manual_filing"])
        self.assertIn("research", {entry["category"] for entry in self.store.categories()})
        self.assertEqual(results[0]["id"], item["id"])
        events = self.store.events_for_item(item["id"], event_type="item.refiled")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["previous_category"], "SQL queries")
        self.assertEqual(events[0]["payload"]["new_category"], "research")
        self.assertIn("customer research", events[0]["payload"]["reason"])

    def test_update_tags_normalizes_dedupes_indexes_and_audits(self):
        item = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            source="clipboard",
            project="skratched",
        )

        updated = self.store.update_tags(
            item["id"],
            [" Follow Up ", "openrouter", "follow up", "proxy/config", ""],
            reason="tag for recall",
        )
        tags = self.store.tags()
        results = self.store.search("proxy/config follow-up")

        self.assertEqual(updated["facets"]["tags"], ["follow-up", "openrouter", "proxy/config"])
        self.assertEqual(updated["tags"], ["follow-up", "openrouter", "proxy/config"])
        self.assertEqual({entry["tag"]: entry["count"] for entry in tags}["follow-up"], 1)
        self.assertEqual(results[0]["id"], item["id"])
        events = self.store.events_for_item(item["id"], event_type="item.tags_updated")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["tags"], ["follow-up", "openrouter", "proxy/config"])
        self.assertIn("tag for recall", events[0]["payload"]["reason"])
        self.assertNotIn("sk-or-v1-qqqq", json.dumps(updated))
        self.assertNotIn("sk-or-v1-qqqq", json.dumps(events))

    def test_suggest_only_capture_stays_in_inbox_until_accepted(self):
        item = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-oooooooooooooooooooooooooooooooooooooooooooooooo",
            source="clipboard",
            project="skratched",
            filing_mode="suggest",
        )

        self.assertEqual(item["category"], "inbox")
        self.assertEqual(item["filing_suggestion"]["target_category"], "API-Keys")
        self.assertEqual(item["filing_suggestion"]["status"], "pending")
        self.assertIn("pattern-based", item["filing_suggestion"]["reason"])
        self.assertNotIn("sk-or-v1-oooo", json.dumps(item))
        self.assertEqual(self.store.categories()[0]["category"], "inbox")
        suggested_events = self.store.events_for_item(item["id"], event_type="item.filing_suggested")
        self.assertEqual(len(suggested_events), 1)
        self.assertEqual(suggested_events[0]["payload"]["target_category"], "API-Keys")

        accepted = self.store.accept_filing_suggestion(item["id"], reason="approve suggestion")

        self.assertEqual(accepted["category"], "API-Keys")
        self.assertEqual(accepted["filing_suggestion"]["status"], "accepted")
        self.assertEqual(accepted["filing_suggestion"]["target_category"], "API-Keys")
        self.assertTrue(accepted["facets"]["manual_filing"])
        accepted_events = self.store.events_for_item(item["id"], event_type="item.filing_suggestion_accepted")
        self.assertEqual(len(accepted_events), 1)
        self.assertEqual(accepted_events[0]["payload"]["previous_category"], "inbox")
        self.assertEqual(accepted_events[0]["payload"]["new_category"], "API-Keys")
        self.assertNotIn("sk-or-v1-oooo", json.dumps(accepted_events))

    def test_undo_last_filing_restores_previous_category(self):
        item = self.store.capture("Prompt: summarize the release notes", source="manual", project="docs")
        self.store.refile_item(item["id"], "follow-up", reason="needs review")

        restored = self.store.undo_last_filing(item["id"], reason="misfiled")

        self.assertEqual(restored["category"], "prompts")
        self.assertFalse(restored["facets"].get("manual_filing", False))
        events = self.store.events_for_item(item["id"])
        event_types = [event["event_type"] for event in events]
        self.assertIn("item.refiled", event_types)
        self.assertIn("item.filing_undone", event_types)
        undone = [event for event in events if event["event_type"] == "item.filing_undone"][0]
        self.assertEqual(undone["payload"]["restored_category"], "prompts")
        self.assertIn("misfiled", undone["payload"]["reason"])


if __name__ == "__main__":
    unittest.main()
