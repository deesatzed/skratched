import base64
import json
import tempfile
import unittest
from pathlib import Path

from server import dispatch_api
from skratched.export import parse_jsonl_export
from skratched.storage import SkratchedStore


class ApiWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SkratchedStore(Path(self.tmp.name) / "skratched.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def api(self, method, path, payload=None):
        status, body = dispatch_api(self.store, method, path, payload or {})
        if status >= 400:
            self.fail(f"{method} {path} returned {status}: {body}")
        return body

    def assert_validation_error(self, method, path, payload, expected_fragment):
        status, body = dispatch_api(self.store, method, path, payload)
        self.assertEqual(status, 400)
        self.assertIn("error", body)
        self.assertIn(expected_fragment, body["error"])
        self.assertNotIn("Traceback", json.dumps(body))
        self.assertNotIn("sk-or-v1-boundary", json.dumps(body))
        return body

    def test_health_api_reports_local_diagnostics(self):
        self.api(
            "POST",
            "/api/capture",
            {
                "text": "Prompt: health diagnostic should be locally searchable",
                "source": "manual",
                "project": "workflow",
            },
        )

        health = self.api("GET", "/api/health")

        self.assertTrue(health["ok"])
        self.assertTrue(health["storage"]["ok"])
        self.assertEqual(health["storage_path"], str(self.store.db_path))
        self.assertIn("items", health["tables"])
        self.assertEqual(health["counts"]["items"], 1)
        self.assertEqual(health["items"], 1)
        self.assertTrue(health["indexes"]["fts"]["ok"])
        self.assertTrue(health["indexes"]["fts"]["fresh"])
        self.assertEqual(health["indexes"]["fts"]["indexed_items"], health["counts"]["items"])
        self.assertTrue(health["search"]["ok"])
        self.assertEqual(health["search"]["probe"], "health")
        self.assertTrue(health["redaction"]["ok"])
        self.assertTrue(health["redaction"]["checks"]["openrouter_key"])
        self.assertTrue(health["redaction"]["checks"]["database_url"])
        self.assertTrue(health["redaction"]["checks"]["bearer_token"])
        self.assertFalse(health["optional_ai"]["required"])
        self.assertTrue(health["optional_ai"]["ok"])
        self.assertTrue(health["event_integrity"]["ok"])
        self.assertEqual(health["event_integrity"]["events"], health["counts"]["events"])
        self.assertEqual(health["event_integrity"]["verified_events"], health["counts"]["events"])
        self.assertEqual(len(health["event_integrity"]["head_hash"]), 64)

    def test_summaries_api_reports_redacted_tiered_rollups(self):
        self.api(
            "POST",
            "/api/capture",
            {
                "text": "Prompt: summarize local routing failures",
                "source": "manual",
                "project": "workflow",
            },
        )
        self.api(
            "POST",
            "/api/capture",
            {
                "text": "OPENROUTER_API_KEY=sk-or-v1-apirollupaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "source": "clipboard",
                "project": "workflow",
            },
        )

        rollups = self.api("GET", "/api/summaries")
        encoded = json.dumps(rollups)
        kinds = {entry["kind"] for entry in rollups["summaries"]}
        scopes = {(entry["scope_type"], entry["scope_value"]) for entry in rollups["summaries"]}

        self.assertIn("rollup:recent", kinds)
        self.assertIn("rollup:project", kinds)
        self.assertIn("rollup:category", kinds)
        self.assertIn("rollup:long_horizon", kinds)
        self.assertIn(("project", "workflow"), scopes)
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-apirollup", encoded)

    def test_core_memory_workflow_through_api_dispatcher(self):
        note = self.api(
            "POST",
            "/api/capture",
            {"text": "OpenRouter key used for local routing test", "source": "note", "project": "workflow"},
        )["item"]
        key = self.api(
            "POST",
            "/api/capture",
            {
                "text": "OPENROUTER_API_KEY=sk-or-v1-kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
                "source": "clipboard",
                "project": "workflow",
            },
        )["item"]
        self.api("POST", "/api/link", {"from_item_id": key["id"], "to_item_id": note["id"], "link_type": "associated_context"})

        search = self.api("GET", "/api/search?q=provider%20credential%20token%20last%203%20weeks")
        encoded = json.dumps(search)
        self.assertEqual(search["results"][0]["id"], key["id"])
        self.assertEqual(search["results"][0]["associated"][0]["id"], note["id"])
        self.assertNotIn("sk-or-v1-kkkk", encoded)

        denied_status, denied_body = dispatch_api(
            self.store,
            "POST",
            "/api/reveal",
            {"item_id": key["id"], "local_unlock": False, "reason": "workflow negative check"},
        )
        self.assertEqual(denied_status, 403)
        self.assertIn("local unlock", denied_body["error"])
        revealed = self.api("POST", "/api/reveal", {"item_id": key["id"], "local_unlock": True, "reason": "workflow unlock"})["item"]
        self.assertIn("sk-or-v1-kkkk", revealed["content"])

        export = self.api("POST", "/api/export/dry-run", {"label": "workflow"})
        preview = self.api("POST", "/api/import/preview", export)
        self.assertGreaterEqual(preview["duplicate_count"], 2)
        report = self.api("POST", "/api/import/redacted", export)
        self.assertEqual(report["imported"], 0)
        self.assertGreaterEqual(report["skipped"], 2)

    def test_artifact_replacement_and_filing_workflow_through_api_dispatcher(self):
        artifact = self.api(
            "POST",
            "/api/capture-file",
            {
                "filename": "Screenshot workflow product.png",
                "media_type": "image/png",
                "content_base64": base64.b64encode(b"\x89PNG\r\n\x1a\nworkflow-image").decode(),
                "source": "screenshot-work",
                "project": "workflow",
            },
        )["item"]
        self.assertEqual(artifact["category"], "screenshots-products")

        old = self.api("POST", "/api/capture", {"text": "Prompt workflow v1: summarize quickly", "source": "manual"})["item"]
        new = self.api("POST", "/api/capture", {"text": "Prompt workflow v2: summarize with citations", "source": "manual"})["item"]
        self.api("POST", "/api/replace", {"old_item_id": old["id"], "new_item_id": new["id"], "reason": "workflow successor"})
        replacements = self.api("GET", "/api/replacements")["replacements"]
        self.assertEqual(replacements[0]["old"]["id"], old["id"])
        self.assertEqual(replacements[0]["new"]["id"], new["id"])

        refiled = self.api("POST", "/api/refile", {"item_id": old["id"], "category": "follow-up", "reason": "workflow refile"})["item"]
        self.assertEqual(refiled["category"], "follow-up")
        self.assertTrue(refiled["facets"]["manual_filing"])
        undone = self.api("POST", "/api/undo-filing", {"item_id": old["id"], "reason": "workflow undo"})["item"]
        self.assertEqual(undone["category"], "prompts")
        self.assertFalse(undone["facets"].get("manual_filing", False))

    def test_item_edit_version_history_workflow_through_api_dispatcher(self):
        old = self.api(
            "POST",
            "/api/capture",
            {
                "text": "OPENROUTER_API_KEY=sk-or-v1-editworkflowaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "source": "clipboard",
                "project": "workflow",
            },
        )["item"]

        edited = self.api(
            "POST",
            "/api/items/edit",
            {
                "item_id": old["id"],
                "text": "OPENROUTER_API_KEY=<OPENROUTER_API_KEY> for workflow placeholder",
                "reason": "replace sk-or-v1-editworkflowaaaaaaaaaaaaaaaaaaaaaaaaaaaa with placeholder",
            },
        )
        history = self.api("GET", f"/api/versions?item_id={old['id']}")
        encoded = json.dumps({"edited": edited, "history": history})

        self.assertEqual(edited["item"]["project"], "workflow")
        self.assertEqual(edited["history"]["latest_item_id"], edited["item"]["id"])
        self.assertEqual(history["latest_item_id"], edited["item"]["id"])
        self.assertEqual(history["edges"][0]["relation"], "edited_to")
        self.assertEqual(history["edges"][0]["old_item_id"], old["id"])
        self.assertEqual(history["edges"][0]["new_item_id"], edited["item"]["id"])
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-editworkflow", encoded)

    def test_action_safety_workflow_through_api_dispatcher(self):
        command = self.api(
            "POST",
            "/api/capture",
            {"text": "rm -rf / --no-preserve-root", "source": "clipboard", "project": "workflow"},
        )["item"]
        sql = self.api(
            "POST",
            "/api/capture",
            {"text": "select id, email from users where active = true;", "source": "clipboard", "project": "workflow"},
        )["item"]

        proposed = self.api("GET", f"/api/actions/propose?item_id={command['id']}&action=reuse")
        checked = self.api("POST", "/api/actions/check", {"item_id": command["id"], "action": "reuse"})
        denied_status, denied_body = dispatch_api(
            self.store,
            "POST",
            "/api/actions/apply",
            {
                "item_id": command["id"],
                "action": "reuse",
                "approved": True,
                "reason": "approve sk-or-v1-actionworkflowaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        )
        caution = self.api(
            "POST",
            "/api/actions/apply",
            {"item_id": sql["id"], "action": "reuse", "approved": True, "reason": "readonly review"},
        )
        encoded = json.dumps({"proposed": proposed, "checked": checked, "denied": denied_body, "caution": caution})

        self.assertEqual(proposed["risk_class"], "blocked")
        self.assertEqual(checked["decision"], "blocked")
        self.assertEqual(denied_status, 403)
        self.assertIn("blocked", denied_body["error"])
        self.assertEqual(caution["status"], "applied")
        self.assertEqual(caution["decision"], "approved")
        self.assertTrue(caution["reversible"])
        self.assertNotIn("sk-or-v1-actionworkflow", encoded)

    def test_screenshot_watch_scan_workflow_through_api_dispatcher(self):
        watch_dir = Path(self.tmp.name) / "screenshots"
        watch_dir.mkdir()
        screenshot = watch_dir / "Screenshot workflow watch.png"
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\nworkflow-watch-image")

        first = self.api(
            "POST",
            "/api/screenshots/scan",
            {"directory": str(watch_dir), "project": "workflow"},
        )
        second = self.api(
            "POST",
            "/api/screenshots/scan",
            {"directory": str(watch_dir), "project": "workflow"},
        )

        encoded = json.dumps({"first": first, "second": second})
        self.assertEqual(first["imported_count"], 1)
        self.assertEqual(first["items"][0]["category"], "screenshots-work")
        self.assertEqual(first["items"][0]["facets"]["observed_path"], str(screenshot.resolve()))
        self.assertEqual(second["imported_count"], 0)
        self.assertEqual(second["skipped_count"], 1)
        self.assertNotIn("workflow-watch-image", encoded)

    def test_bounded_screenshot_watcher_workflow_through_api_dispatcher(self):
        watch_dir = Path(self.tmp.name) / "screenshots"
        watch_dir.mkdir()
        screenshot = watch_dir / "Screenshot workflow watcher.png"
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\nworkflow-watcher-image")

        report = self.api(
            "POST",
            "/api/screenshots/watch-run",
            {"directory": str(watch_dir), "project": "workflow", "max_cycles": 2, "interval_seconds": 0},
        )

        encoded = json.dumps(report)
        self.assertEqual(report["cycles"], 2)
        self.assertEqual(report["imported_count"], 1)
        self.assertEqual(report["skipped_count"], 1)
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(report["stopped_reason"], "max_cycles")
        self.assertEqual(report["items"][0]["facets"]["observed_path"], str(screenshot.resolve()))
        self.assertNotIn("workflow-watcher-image", encoded)

    def test_shelf_creation_workflow_is_idempotent(self):
        first = self.api("POST", "/api/shelves", {"category": "triage", "reason": "workflow shelf"})
        second = self.api("POST", "/api/shelves", {"category": "triage", "reason": "duplicate workflow shelf"})

        categories = {entry["category"]: entry["count"] for entry in second["categories"]}
        self.assertEqual(first["shelf"]["id"], second["shelf"]["id"])
        self.assertEqual(categories["triage"], 0)
        self.assertEqual(self.store.count_rows("shelves"), 1)

    def test_context_api_returns_memory_map_contract(self):
        root = self.api(
            "POST",
            "/api/capture",
            {
                "text": "OPENROUTER_API_KEY=sk-or-v1-mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm",
                "source": "clipboard",
                "project": "workflow",
            },
        )["item"]
        note = self.api(
            "POST",
            "/api/capture",
            {"text": "OpenRouter key is used by the workflow proxy", "source": "note", "project": "workflow"},
        )["item"]
        self.api("POST", "/api/link", {"from_item_id": root["id"], "to_item_id": note["id"], "link_type": "used_with"})

        graph = self.api("GET", f"/api/context?item_id={root['id']}")
        encoded = json.dumps(graph)

        self.assertEqual(graph["summary"]["root_category"], "API-Keys")
        self.assertEqual(graph["summary"]["node_count"], 2)
        self.assertEqual(graph["summary"]["edge_types"]["used_with"], 1)
        self.assertEqual(graph["clusters"][0]["name"], "linked context")
        self.assertEqual(graph["clusters"][0]["item_ids"], [note["id"]])
        self.assertTrue(graph["memory_hints"])
        self.assertNotIn("sk-or-v1-mmmm", encoded)

    def test_suggest_only_filing_workflow_through_api_dispatcher(self):
        captured = self.api(
            "POST",
            "/api/capture",
            {
                "text": "select id, email from users where active = true;",
                "source": "clipboard",
                "project": "workflow",
                "filing_mode": "suggest",
            },
        )["item"]

        self.assertEqual(captured["category"], "inbox")
        self.assertEqual(captured["filing_suggestion"]["target_category"], "SQL queries")
        self.assertEqual(captured["filing_suggestion"]["status"], "pending")

        accepted = self.api(
            "POST",
            "/api/filing-suggestions/accept",
            {"item_id": captured["id"], "reason": "workflow accept"},
        )["item"]

        self.assertEqual(accepted["category"], "SQL queries")
        self.assertEqual(accepted["filing_suggestion"]["status"], "accepted")
        self.assertEqual(accepted["facets"]["manual_previous_category"], "inbox")
        categories = {entry["category"]: entry["count"] for entry in self.api("GET", "/api/categories")["categories"]}
        self.assertEqual(categories["SQL queries"], 1)

    def test_tag_editing_workflow_through_api_dispatcher(self):
        item = self.api(
            "POST",
            "/api/capture",
            {
                "text": "Prompt: compare OpenRouter model routing options",
                "source": "manual",
                "project": "workflow",
            },
        )["item"]

        updated = self.api(
            "POST",
            "/api/tags",
            {"item_id": item["id"], "tags": ["Model Routing", "openrouter", "model routing"], "reason": "workflow tags"},
        )["item"]
        tags = self.api("GET", "/api/tags")["tags"]
        search = self.api("GET", "/api/search?q=model-routing")

        self.assertEqual(updated["tags"], ["model-routing", "openrouter"])
        self.assertEqual({entry["tag"]: entry["count"] for entry in tags}["model-routing"], 1)
        self.assertEqual(search["results"][0]["id"], item["id"])

    def test_api_rejects_non_object_post_payloads_without_tracebacks(self):
        self.assert_validation_error(
            "POST",
            "/api/capture",
            ["OPENROUTER_API_KEY=sk-or-v1-boundarybbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "JSON object",
        )

    def test_api_reports_missing_required_identifiers_as_safe_400s(self):
        item = self.api("POST", "/api/capture", {"text": "Prompt: boundary validation", "source": "manual"})["item"]

        cases = [
            ("/api/link", {"from_item_id": item["id"]}, "to_item_id"),
            ("/api/tags", {"tags": ["boundary"]}, "item_id"),
            ("/api/reveal", {"reason": "sk-or-v1-boundaryrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"}, "item_id"),
            ("/api/replace", {"old_item_id": item["id"]}, "new_item_id"),
            ("/api/refile", {"item_id": item["id"]}, "category"),
            ("/api/filing-suggestions/accept", {"reason": "accept later"}, "item_id"),
            ("/api/undo-filing", {"reason": "undo later"}, "item_id"),
        ]
        for path, payload, expected in cases:
            with self.subTest(path=path):
                self.assert_validation_error("POST", path, payload, expected)

    def test_api_validates_numeric_bounds_before_watcher_or_scan_work(self):
        for path in ["/api/screenshots/scan", "/api/screenshots/watch-run"]:
            with self.subTest(path=path):
                self.assert_validation_error("POST", path, {"directory": self.tmp.name, "limit": "many"}, "limit")
                self.assert_validation_error("POST", path, {"directory": self.tmp.name, "limit": 0}, "limit")
                self.assert_validation_error("POST", path, {"directory": self.tmp.name, "limit": 1000}, "limit")

        self.assert_validation_error(
            "POST",
            "/api/screenshots/watch-run",
            {"directory": self.tmp.name, "max_cycles": 0},
            "max_cycles",
        )
        self.assert_validation_error(
            "POST",
            "/api/screenshots/watch-run",
            {"directory": self.tmp.name, "interval_seconds": -1},
            "interval_seconds",
        )

    def test_export_dry_run_redacts_user_supplied_label(self):
        self.api("POST", "/api/capture", {"text": "Prompt: export label validation", "source": "manual"})

        bundle = self.api(
            "POST",
            "/api/export/dry-run",
            {"label": "workflow sk-or-v1-boundaryllllllllllllllllllllllllllllllllllllllll"},
        )

        encoded = json.dumps(bundle)
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-boundary", encoded)

    def test_import_failure_returns_safe_diagnostic_and_retry_options(self):
        payload = {
            "schema": "skratched.export.v1",
            "mode": "dry-run",
            "label": "bad sk-or-v1-importdiagaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "items": [],
            "item_count": 0,
            "bundle_hash": "not-a-real-hash",
        }

        status, body = dispatch_api(self.store, "POST", "/api/import/preview", payload)
        encoded = json.dumps(body)

        self.assertEqual(status, 400)
        self.assertIn("error", body)
        self.assertEqual(body["diagnostic"]["schema"], "skratched.error_diagnostic.v1")
        self.assertEqual(body["diagnostic"]["operation"], "import.preview")
        self.assertTrue(body["diagnostic"]["storage"]["ok"])
        self.assertTrue(body["diagnostic"]["indexes"]["fts"]["ok"])
        self.assertTrue(body["diagnostic"]["redaction"]["ok"])
        self.assertIn("retry_options", body["diagnostic"])
        self.assertIn("Re-run import preview with an exported redacted bundle or JSONL payload.", body["diagnostic"]["retry_options"])
        self.assertNotIn("Traceback", encoded)
        self.assertNotIn("sk-or-v1-importdiag", encoded)

    def test_jsonl_import_failure_returns_safe_diagnostic_and_retry_options(self):
        bad_jsonl = '{"record_type":"manifest","schema":"skratched.export_jsonl.v1","label":"sk-or-v1-jsonldiagaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n'

        status, body = dispatch_api(self.store, "POST", "/api/import/jsonl/preview", {"jsonl": bad_jsonl})
        encoded = json.dumps(body)

        self.assertEqual(status, 400)
        self.assertEqual(body["diagnostic"]["operation"], "import.jsonl_preview")
        self.assertTrue(body["diagnostic"]["storage"]["ok"])
        self.assertIn("Validate that the bundle hash/footer is present and unchanged.", body["diagnostic"]["retry_options"])
        self.assertNotIn("sk-or-v1-jsonldiag", encoded)

    def test_jsonl_export_preview_and_import_workflow_through_api_dispatcher(self):
        item = self.api(
            "POST",
            "/api/capture",
            {
                "text": "OPENROUTER_API_KEY=sk-or-v1-jsonlworkflowjsonlworkflowjsonlworkflow",
                "source": "clipboard",
                "project": "workflow",
            },
        )["item"]

        exported = self.api("POST", "/api/export/jsonl", {"label": "jsonl-workflow"})
        preview = self.api("POST", "/api/import/jsonl/preview", {"jsonl": exported["jsonl"]})
        report = self.api("POST", "/api/import/jsonl", {"jsonl": exported["jsonl"]})

        encoded = json.dumps({"exported": exported, "preview": preview, "report": report})
        self.assertEqual(exported["schema"], "skratched.export_jsonl.v1")
        self.assertEqual(exported["item_count"], 1)
        self.assertEqual(preview["item_count"], 1)
        self.assertTrue(preview["entries"][0]["entry_id"].startswith("export_entry_"))
        self.assertEqual(preview["entries"][0]["item_id"], item["id"])
        self.assertEqual(report["imported"], 0)
        self.assertEqual(report["skipped"], 1)
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-jsonlworkflow", encoded)

    def test_jsonl_export_file_save_workflow_through_api_dispatcher(self):
        self.api(
            "POST",
            "/api/capture",
            {
                "text": "OPENROUTER_API_KEY=sk-or-v1-jsonlfileworkflowaaaaaaaaaaaaaaaaaaaa",
                "source": "clipboard",
                "project": "workflow",
            },
        )

        saved = self.api(
            "POST",
            "/api/export/jsonl/save",
            {"label": "file workflow sk-or-v1-jsonlfileworkflowaaaaaaaaaaaaaaaaaaaa"},
        )
        path = Path(saved["path"])
        parsed = parse_jsonl_export(path.read_text())
        encoded = json.dumps({"saved": saved, "jsonl": path.read_text()})

        self.assertEqual(saved["schema"], "skratched.export_file.v1")
        self.assertEqual(saved["format"], "jsonl")
        self.assertEqual(path.parent.resolve(), (self.store.db_path.parent / "exports").resolve())
        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(parsed["bundle_hash"], saved["bundle_hash"])
        self.assertIn("[REDACTED:openrouter_key]", encoded)
        self.assertNotIn("sk-or-v1-jsonlfileworkflow", encoded)


if __name__ == "__main__":
    unittest.main()
