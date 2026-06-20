import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from skratched.mcp_server import (
    build_app,
    confirm_reveal,
    parse_allowed_roots,
    skratched_capture,
    skratched_context,
    skratched_health,
    skratched_reveal,
    skratched_search,
    skratched_workspace_scan,
)
from skratched.storage import SkratchedStore


class ConfirmRevealTests(unittest.TestCase):
    def test_confirmed_when_tty_answers_y(self):
        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", return_value="y"
        ):
            self.assertTrue(confirm_reveal("item-1", "writing to .env"))

    def test_confirmed_when_tty_answers_yes_case_insensitive(self):
        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", return_value="YES"
        ):
            self.assertTrue(confirm_reveal("item-1", "writing to .env"))

    def test_declined_when_tty_answers_n(self):
        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", return_value="n"
        ):
            self.assertFalse(confirm_reveal("item-1", "writing to .env"))

    def test_declined_when_tty_answers_blank(self):
        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", return_value=""
        ):
            self.assertFalse(confirm_reveal("item-1", "writing to .env"))

    def test_declined_when_tty_answers_garbage(self):
        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", return_value="sure whatever"
        ):
            self.assertFalse(confirm_reveal("item-1", "writing to .env"))

    def test_declined_when_no_tty_attached(self):
        with patch("sys.stdin.isatty", return_value=False), patch(
            "builtins.input"
        ) as mock_input:
            self.assertFalse(confirm_reveal("item-1", "writing to .env"))
            mock_input.assert_not_called()

    def test_declined_when_input_raises_eof(self):
        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", side_effect=EOFError
        ):
            self.assertFalse(confirm_reveal("item-1", "writing to .env"))

    def test_declined_when_input_raises_keyboard_interrupt(self):
        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", side_effect=KeyboardInterrupt
        ):
            self.assertFalse(confirm_reveal("item-1", "writing to .env"))

    def test_prompt_includes_item_id_and_reason_without_leaking_secret_value(self):
        captured = {}

        def fake_input(prompt):
            captured["prompt"] = prompt
            return "n"

        with patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", side_effect=fake_input
        ):
            confirm_reveal("item-42", "debugging auth flow")

        self.assertIn("item-42", captured["prompt"])
        self.assertIn("debugging auth flow", captured["prompt"])


class ReadToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SkratchedStore(Path(self.tmp.name) / "skratched.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_health_matches_store_health_report(self):
        result = skratched_health(store=self.store)

        self.assertEqual(result, self.store.health_report())
        self.assertTrue(result["ok"])

    def test_search_returns_redacted_results_matching_store_search(self):
        self.store.capture(
            text="OPENROUTER_API_KEY=sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="demo",
        )

        result = skratched_search("openrouter", store=self.store)

        self.assertEqual(result["query"], "openrouter")
        self.assertEqual(len(result["results"]), 1)
        preview = result["results"][0]["preview"]
        self.assertNotIn("sk-or-v1-aaaaaaaa", preview)
        self.assertIn("[REDACTED:openrouter_key]", preview)

    def test_search_matches_store_search_exactly(self):
        self.store.capture(text="some note about caching", project="demo")

        result = skratched_search("caching", store=self.store)

        self.assertEqual(result["results"], self.store.search("caching"))

    def test_context_returns_graph_for_known_item(self):
        item = self.store.capture(text="a note worth linking later", project="demo")

        result = skratched_context(item["id"], store=self.store)

        self.assertEqual(result["root"]["id"], item["id"])
        self.assertEqual(result["root"]["graph_depth"], 0)
        self.assertIn("nodes", result)
        self.assertIn("edges", result)

    def test_context_raises_clean_error_for_unknown_item(self):
        with self.assertRaises(ValueError):
            skratched_context("does-not-exist", store=self.store)


class CaptureToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SkratchedStore(Path(self.tmp.name) / "skratched.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_capture_persists_and_returns_item(self):
        result = skratched_capture(
            "a useful snippet",
            project="demo",
            source="agent",
            store=self.store,
        )

        self.assertEqual(result["facets"]["source"], "agent")
        stored = self.store.get_item(result["id"])
        self.assertEqual(stored["id"], result["id"])

    def test_capture_matches_store_capture_for_same_input(self):
        result = skratched_capture("a second note", project="demo", store=self.store)
        direct = self.store.get_item(result["id"])

        self.assertEqual(result["category"], direct["category"])
        self.assertEqual(result["preview"], direct["preview"])

    def test_capture_redacts_secret_text_same_as_rest_api(self):
        result = skratched_capture(
            "OPENROUTER_API_KEY=sk-or-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            project="demo",
            source="clipboard",
            store=self.store,
        )

        self.assertNotIn("sk-or-v1-bbbbb", result["preview"])
        self.assertIn("[REDACTED:openrouter_key]", result["preview"])

    def test_capture_requires_non_blank_text(self):
        with self.assertRaises(ValueError):
            skratched_capture("   ", project="demo", store=self.store)


class ParseAllowedRootsTests(unittest.TestCase):
    def test_parses_path_separator_delimited_list(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            roots = parse_allowed_roots(f"{a}{os.pathsep}{b}")

        self.assertEqual(len(roots), 2)

    def test_empty_or_unset_returns_no_roots(self):
        self.assertEqual(parse_allowed_roots(None), [])
        self.assertEqual(parse_allowed_roots(""), [])
        self.assertEqual(parse_allowed_roots("   "), [])


class WorkspaceScanToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SkratchedStore(Path(self.tmp.name) / "skratched.db")
        self.scan_root = Path(self.tmp.name) / "approved_root"
        self.scan_root.mkdir()
        (self.scan_root / "notes.txt").write_text("hello", encoding="utf-8")
        self.outside_root = Path(self.tmp.name) / "outside_root"
        self.outside_root.mkdir()
        # Mirrors the real call path: allowed_roots always comes from
        # parse_allowed_roots(), which resolves symlinks (e.g. macOS /tmp ->
        # /private/tmp). Building the allowlist from a raw, unresolved Path
        # here would make the allowlist comparison fail for legitimate roots.
        self.allowed = parse_allowed_roots(str(self.scan_root))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_scan_succeeds_for_root_inside_allowlist(self):
        result = skratched_workspace_scan(
            str(self.scan_root),
            store=self.store,
            allowed_roots=self.allowed,
        )

        self.assertIn("candidates", result)

    def test_scan_rejects_root_outside_allowlist(self):
        with self.assertRaises(ValueError) as ctx:
            skratched_workspace_scan(
                str(self.outside_root),
                store=self.store,
                allowed_roots=self.allowed,
            )

        self.assertIn("SKRATCHED_MCP_ALLOWED_ROOTS", str(ctx.exception))

    def test_scan_rejects_when_no_allowlist_configured(self):
        with self.assertRaises(ValueError) as ctx:
            skratched_workspace_scan(
                str(self.scan_root),
                store=self.store,
                allowed_roots=[],
            )

        self.assertIn("SKRATCHED_MCP_ALLOWED_ROOTS", str(ctx.exception))

    def test_scan_allows_subdirectory_of_allowed_root(self):
        sub = self.scan_root / "nested"
        sub.mkdir()

        result = skratched_workspace_scan(
            str(sub),
            store=self.store,
            allowed_roots=self.allowed,
        )

        self.assertIn("candidates", result)

    def test_scan_rejects_symlink_escape_outside_allowlist(self):
        escape_link = self.scan_root / "escape"
        escape_link.symlink_to(self.outside_root)

        with self.assertRaises(ValueError):
            skratched_workspace_scan(
                str(escape_link),
                store=self.store,
                allowed_roots=self.allowed,
            )


class RevealToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SkratchedStore(Path(self.tmp.name) / "skratched.db")
        self.secret_item = self.store.capture(
            text="OPENROUTER_API_KEY=sk-or-v1-cccccccccccccccccccccccccccccccccccccccccccccccc",
            source="clipboard",
            project="demo",
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_reveal_returns_real_value_when_confirmed(self):
        result = skratched_reveal(
            self.secret_item["id"],
            "writing to local .env",
            store=self.store,
            confirm=lambda item_id, reason: True,
        )

        self.assertTrue(result["confirmed"])
        self.assertIn("sk-or-v1-cccccccccc", result["item"]["content"])

    def test_reveal_stays_redacted_when_declined(self):
        result = skratched_reveal(
            self.secret_item["id"],
            "writing to local .env",
            store=self.store,
            confirm=lambda item_id, reason: False,
        )

        self.assertFalse(result["confirmed"])
        self.assertNotIn("content", result)
        self.assertNotIn("sk-or-v1-cccccccccc", str(result))

    def test_reveal_never_calls_confirm_hook_with_secret_value(self):
        captured = {}

        def fake_confirm(item_id, reason):
            captured["item_id"] = item_id
            captured["reason"] = reason
            return False

        skratched_reveal(
            self.secret_item["id"],
            "debugging auth",
            store=self.store,
            confirm=fake_confirm,
        )

        self.assertEqual(captured["item_id"], self.secret_item["id"])
        self.assertEqual(captured["reason"], "debugging auth")
        self.assertNotIn("sk-or-v1", str(captured))

    def test_reveal_logs_audit_event_on_confirmation(self):
        skratched_reveal(
            self.secret_item["id"],
            "writing to local .env",
            store=self.store,
            confirm=lambda item_id, reason: True,
        )

        events = self.store.events_for_item(self.secret_item["id"], event_type="item.revealed")
        self.assertEqual(len(events), 1)

    def test_reveal_logs_denied_event_on_decline(self):
        skratched_reveal(
            self.secret_item["id"],
            "writing to local .env",
            store=self.store,
            confirm=lambda item_id, reason: False,
        )

        events = self.store.events_for_item(self.secret_item["id"], event_type="item.reveal_denied")
        self.assertEqual(len(events), 1)

    def test_reveal_unknown_item_raises_clean_error(self):
        with self.assertRaises(ValueError):
            skratched_reveal(
                "does-not-exist",
                "reason",
                store=self.store,
                confirm=lambda item_id, reason: True,
            )


class BuildAppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SkratchedStore(Path(self.tmp.name) / "skratched.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_app_registers_exactly_six_tools(self):
        app = build_app(store=self.store, allowed_roots=[])

        tools = asyncio.run(app.list_tools())
        names = {tool.name for tool in tools}

        self.assertEqual(len(tools), 6)
        self.assertEqual(
            names,
            {
                "skratched_health_tool",
                "skratched_search_tool",
                "skratched_context_tool",
                "skratched_capture_tool",
                "skratched_workspace_scan_tool",
                "skratched_reveal_tool",
            },
        )

    def test_registered_search_tool_executes_against_store(self):
        self.store.capture(text="a registered-tool smoke test note", project="demo")
        app = build_app(store=self.store, allowed_roots=[])

        _content, structured = asyncio.run(
            app.call_tool("skratched_search_tool", {"query": "smoke test"})
        )

        self.assertEqual(len(structured["results"]), 1)
        self.assertEqual(structured["results"][0]["preview"], "a registered-tool smoke test note")


if __name__ == "__main__":
    unittest.main()
