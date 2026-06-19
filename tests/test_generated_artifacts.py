import json
import subprocess
import sys
import unittest


class GeneratedArtifactParityTests(unittest.TestCase):
    def test_demo_flow_output_matches_documented_schema_and_invariants(self):
        result = subprocess.run(
            [sys.executable, "scripts/demo_flow.py"],
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(result.stdout)

        self.assertEqual(payload["schema"], "skratched.demo_flow.v1")
        self.assertTrue(payload["passed"])
        self.assertTrue(payload["raw_secret_redacted"])
        self.assertTrue(payload["stale_key_excluded"])
        self.assertGreaterEqual(payload["associated_count"], 1)
        self.assertIn("associated_context", payload["associated_link_types"])
        self.assertEqual(payload["top"]["category"], "API-Keys")
        self.assertIn("[REDACTED:openrouter_key]", payload["top"]["preview"])
        self.assertNotIn("sk-or-v1-demo", result.stdout)


if __name__ == "__main__":
    unittest.main()
