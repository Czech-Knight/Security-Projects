import json
import tempfile
import unittest
from pathlib import Path

from app.core.startup_detector import detect_repository


class StartupDetectorTests(unittest.TestCase):
    def test_detects_npm_start(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package.json").write_text(json.dumps({"scripts": {"start": "node app.js"}}), encoding="utf-8")
            result = detect_repository(root)
            commands = [item["command"] for item in result["startup_candidates"]]
            self.assertIn("npm run start", commands)
            self.assertIn("Node.js", result["stacks"])

    def test_detects_django(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "manage.py").write_text("# django", encoding="utf-8")
            result = detect_repository(root)
            self.assertEqual(result["startup_candidates"][0]["command"], "python manage.py runserver 127.0.0.1:8000")


if __name__ == "__main__":
    unittest.main()
