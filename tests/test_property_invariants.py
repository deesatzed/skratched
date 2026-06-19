import json
import tempfile
import unittest
from pathlib import Path

from skratched.export import (
    build_dry_run_export,
    build_jsonl_export,
    import_redacted_bundle,
    import_redacted_jsonl,
)
from skratched.storage import SkratchedStore


class PropertyInvariantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SkratchedStore(Path(self.tmp.name) / "skratched.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_redaction_and_duplicate_family_invariants_hold_across_secret_variants(self):
        cases = [
            (
                "openrouter",
                "OPENROUTER_API_KEY=sk-or-v1-propopenrouteraaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sk-or-v1-propopenrouteraaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "database",
                "DATABASE_URL=postgresql://app_user:propDbSecret123@db.local/app",
                "propDbSecret123",
            ),
            (
                "bearer",
                'curl -H "Authorization: Bearer propBearerSecret1234567890" https://api.example.test',
                "propBearerSecret",
            ),
            (
                "json",
                '{"api_key": "propJsonSecret1234567890", "safe": true}',
                "propJsonSecret",
            ),
        ]

        for label, text, raw_marker in cases:
            with self.subTest(label=label):
                first = self.store.capture(text, source="clipboard", project="properties")
                duplicate = self.store.capture(text, source="clipboard", project="properties")
                results = self.store.search(text)
                bundle = build_dry_run_export(self.store, label=f"prop-{label}-{text}")
                events = self.store.events_for_item(first["id"]) + self.store.events_for_item(None)
                encoded = json.dumps(
                    {"first": first, "duplicate": duplicate, "results": results, "bundle": bundle, "events": events}
                )

                self.assertEqual(first["content_hash"], duplicate["content_hash"])
                self.assertEqual(first["family_id"], duplicate["family_id"])
                self.assertNotIn(raw_marker, encoded)
                self.assertNotIn("content", first)
                self.assertTrue(any(marker in encoded for marker in ("[REDACTED:openrouter_key]", "[REDACTED:secret]", "[REDACTED:credentials]", "[REDACTED:bearer_token]")))

    def test_bundle_and_jsonl_import_paths_restore_equivalent_searchable_metadata(self):
        sql = self.store.capture(
            "select id, email from users where active = true;",
            source="clipboard",
            project="crm",
        )
        code = self.store.capture(
            "from pathlib import Path\n\ndef route_screenshot(path):\n    return Path(path).name\n",
            source="clipboard",
            project="skratched",
            path="router.py",
        )
        url = self.store.capture(
            "Reference https://docs.example.test/guide?api_key=propUrlSecret1234567890&page=1",
            source="clipboard",
            project="docs",
        )
        long_note = self.store.capture("Long prompt\n" + ("chunk invariant " * 520), source="manual", project="docs")

        bundle = build_dry_run_export(self.store, label="differential-json")
        jsonl = build_jsonl_export(self.store, label="differential-jsonl")
        with tempfile.TemporaryDirectory() as tmp:
            bundle_store = SkratchedStore(Path(tmp) / "bundle.db")
            jsonl_store = SkratchedStore(Path(tmp) / "jsonl.db")
            try:
                bundle_report = import_redacted_bundle(bundle_store, bundle)
                jsonl_report = import_redacted_jsonl(jsonl_store, jsonl)
                for source in (sql, code, url, long_note):
                    with self.subTest(item=source["id"]):
                        bundle_item = bundle_store.get_item(source["id"])
                        jsonl_item = jsonl_store.get_item(source["id"])
                        bundle_facets = {key: value for key, value in bundle_item["facets"].items() if key != "imported_from"}
                        jsonl_facets = {key: value for key, value in jsonl_item["facets"].items() if key != "imported_from"}
                        self.assertEqual(bundle_item["category"], jsonl_item["category"])
                        self.assertEqual(bundle_item["content_hash"], jsonl_item["content_hash"])
                        self.assertEqual(bundle_facets, jsonl_facets)
                        self.assertEqual(bundle_item["chunks"], jsonl_item["chunks"])

                query_expectations = [
                    ("users active sql", sql["id"]),
                    ("route_screenshot pathlib", code["id"]),
                    ("docs.example.test guide", url["id"]),
                    ("chunk invariant", long_note["id"]),
                ]
                for query, expected_id in query_expectations:
                    with self.subTest(query=query):
                        self.assertEqual(bundle_store.search(query)[0]["id"], expected_id)
                        self.assertEqual(jsonl_store.search(query)[0]["id"], expected_id)
            finally:
                bundle_store.close()
                jsonl_store.close()

        encoded = json.dumps({"bundle": bundle, "jsonl": jsonl, "bundle_report": bundle_report, "jsonl_report": jsonl_report})
        self.assertEqual(bundle_report["imported"], 4)
        self.assertEqual(jsonl_report["imported"], 4)
        self.assertNotIn("propUrlSecret", encoded)

    def test_chunk_manifest_invariants_hold_across_long_artifact_sizes(self):
        sizes = [260, 520, 780]
        for multiplier in sizes:
            with self.subTest(multiplier=multiplier):
                item = self.store.capture(
                    "Chunk property header\n" + ("alpha beta gamma delta " * multiplier),
                    source="manual",
                    project="chunks",
                )
                bundle = build_dry_run_export(self.store, label=f"chunk-{multiplier}")
                entry = next(row for row in bundle["items"] if row["id"] == item["id"])
                chunks = entry["chunk_manifest"]

                self.assertEqual(entry["facets"]["chunk_count"], len(chunks))
                self.assertGreater(len(chunks), 1)
                self.assertEqual(chunks[0]["index"], 0)
                self.assertEqual(chunks[0]["start"], 0)
                self.assertEqual(chunks[0]["overlap_before"], 0)
                for previous, current in zip(chunks, chunks[1:]):
                    self.assertEqual(current["index"], previous["index"] + 1)
                    self.assertGreater(current["start"], previous["start"])
                    self.assertGreater(current["end"], current["start"])
                    self.assertEqual(current["length"], current["end"] - current["start"])
                    self.assertGreaterEqual(current["overlap_before"], 0)
                    self.assertEqual(len(current["hash"]), 64)
                    self.assertNotIn("text", current)

    def test_context_assembly_stays_bounded_deduped_and_redacted_with_cycles(self):
        root = self.store.capture(
            "OPENROUTER_API_KEY=sk-or-v1-contextpropaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source="clipboard",
            project="graph",
            created_at="2026-06-18T10:00:00Z",
        )
        note = self.store.capture(
            "Proxy note explains how the OpenRouter key is used.",
            source="note",
            project="graph",
            created_at="2026-06-18T10:01:00Z",
        )
        screenshot = self.store.capture(
            "Screenshot note shows the proxy settings panel.",
            source="manual",
            project="graph",
            created_at="2026-06-18T10:02:00Z",
        )
        unrelated = self.store.capture(
            "Third-hop unrelated branch should remain outside default context.",
            source="manual",
            project="graph",
            created_at="2026-06-18T10:03:00Z",
        )
        self.store.link_items(root["id"], note["id"], "associated_context")
        self.store.link_items(note["id"], screenshot["id"], "screenshot_of")
        self.store.link_items(screenshot["id"], root["id"], "follow_up_to")
        self.store.link_items(screenshot["id"], unrelated["id"], "mentions")

        graph = self.store.context_graph(root["id"])
        encoded = json.dumps(graph)
        node_ids = [node["id"] for node in graph["nodes"]]
        edge_pairs = {(edge["from"], edge["to"], edge["type"]) for edge in graph["edges"]}

        self.assertEqual(len(node_ids), len(set(node_ids)))
        self.assertIn(root["id"], node_ids)
        self.assertIn(note["id"], node_ids)
        self.assertIn(screenshot["id"], node_ids)
        self.assertIn(unrelated["id"], node_ids)
        self.assertEqual(graph["summary"]["node_count"], len(node_ids))
        self.assertLessEqual(max(int(node.get("graph_depth", 0)) for node in graph["nodes"]), 2)
        self.assertIn((root["id"], note["id"], "associated_context"), edge_pairs)
        self.assertIn("linked context", {cluster["name"] for cluster in graph["clusters"]})
        self.assertNotIn("sk-or-v1-contextprop", encoded)


if __name__ == "__main__":
    unittest.main()
