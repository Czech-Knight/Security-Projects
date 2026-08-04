import tempfile
import unittest
from pathlib import Path

from app.core.builtin_scanner import scan


class BuiltinScannerTests(unittest.TestCase):
    def test_finds_sensitive_logging_and_eval(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.js").write_text("console.log(req.body);\nconst x = eval(userInput);", encoding="utf-8")
            findings = scan(root)
            categories = {item["category"] for item in findings}
            self.assertIn("sensitive-body-logging", categories)
            self.assertIn("dangerous-eval", categories)

    def test_redacts_no_data_because_builtin_does_not_collect_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config.py").write_text('password = "example-password"', encoding="utf-8")
            findings = scan(root)
            self.assertTrue(any(item["category"] == "hardcoded-password" for item in findings))


if __name__ == "__main__":
    unittest.main()
