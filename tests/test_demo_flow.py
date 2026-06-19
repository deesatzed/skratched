import json
import subprocess
import sys
import unittest
from pathlib import Path


class DemoFlowTests(unittest.TestCase):
    def test_demo_flow_proves_openrouter_key_memory_query(self):
        root = Path(__file__).resolve().parents[1]

        result = subprocess.run(
            [sys.executable, "scripts/demo_flow.py"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        encoded = json.dumps(payload)

        self.assertEqual(payload["schema"], "skratched.demo_flow.v1")
        self.assertTrue(payload["passed"])
        self.assertEqual(payload["query"], "find my last OpenRouter API keys added in the last 3 weeks")
        self.assertEqual(payload["top"]["category"], "API-Keys")
        self.assertIn("[REDACTED:openrouter_key]", payload["top"]["preview"])
        self.assertGreaterEqual(payload["associated_count"], 1)
        self.assertIn("associated_context", payload["associated_link_types"])
        self.assertTrue(payload["stale_key_excluded"])
        self.assertTrue(payload["raw_secret_redacted"])
        self.assertNotIn("sk-or-v1-demo", encoded)


if __name__ == "__main__":
    unittest.main()
