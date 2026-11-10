import unittest

from modules.email_parser import parse_email
from modules.detection_engine import analyze_email
from modules.header_analyzer import analyze_headers


class CorePipelineTests(unittest.TestCase):
    def test_parser_extracts_basic_fields_and_url(self):
        raw = """From: security@example.test
To: analyst@example.test
Subject: Account update

Please review the notice at https://example.test/account
"""
        parsed = parse_email(raw)
        self.assertIn("security@example.test", str(parsed.get("sender", "")))
        self.assertEqual(parsed.get("subject"), "Account update")
        self.assertIn("https://example.test/account", parsed.get("urls", []))

    def test_rule_engine_flags_synthetic_credential_phishing(self):
        raw = """From: security@example.test
To: analyst@example.test
Subject: Urgent account verification

Your account will be suspended within 24 hours.
Verify your account immediately and enter your password:
http://192.0.2.10/login
"""
        result = analyze_email(parse_email(raw))
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertEqual(result["risk_level"], "High")
        self.assertTrue(result["findings"])

    def test_rule_engine_does_not_flag_plain_newsletter(self):
        raw = """From: news@example.test
To: analyst@example.test
Subject: Monthly newsletter

Here are the monthly product updates and release notes.
No action is required.
"""
        result = analyze_email(parse_email(raw))
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Low")

    def test_header_analyzer_detects_reply_to_mismatch(self):
        raw = """From: security@example.test
Reply-To: reply@other-example.test
Return-Path: bounce@example.test
Subject: Notice

Hello.
"""
        parsed = parse_email(raw)
        result = analyze_headers(parsed)
        serialized = str(result).lower()
        self.assertTrue("reply" in serialized or "mismatch" in serialized)


if __name__ == "__main__":
    unittest.main()
