from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

from cowork_ai_os.safety import detect_secrets


class MarkdownSecretScanTests(unittest.TestCase):
    def test_markdown_escaped_empty_value_is_not_a_secret(self) -> None:
        self.assertEqual(detect_secrets(b"> secret: \\[\\]\n"), [])

    def test_markdown_escaped_real_value_is_still_detected(self) -> None:
        self.assertIn(
            "assigned-secret",
            detect_secrets(b"> token: \\[synthetic-value\\]\n"),
        )

    def test_markdown_escaped_redaction_marker_is_inert(self) -> None:
        self.assertEqual(
            detect_secrets(b"> authorization: \\[REDACTED:SECRET\\]\n"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
