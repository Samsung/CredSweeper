import unittest

from credsweeper.deep_scanner.eml_scanner import EmlScanner


class TestEmlScanner(unittest.TestCase):

    def test_match_p(self):
        # Valid EML format with all required headers
        eml_data = b"Date: Mon, 1 Jan 2024 12:00:00 +0000\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test Email\n\nEmail body"
        self.assertTrue(EmlScanner.match(eml_data))

        # EML format with headers at the beginning
        eml_data2 = b"Date: Mon, 1 Jan 2024 12:00:00 +0000\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test Email"
        self.assertTrue(EmlScanner.match(eml_data2))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(TypeError):
            EmlScanner.match(None)
        with self.assertRaises(TypeError):
            EmlScanner.match(1)
        # Missing required headers
        self.assertFalse(
            EmlScanner.match(b"Date: Mon, 1 Jan 2024 12:00:00 +0000\nFrom: sender@example.com\nSubject: Test Email"))
        self.assertFalse(EmlScanner.match(b"From: sender@example.com\nTo: recipient@example.com\nSubject: Test Email"))
        self.assertFalse(
            EmlScanner.match(b"Date: Mon, 1 Jan 2024 12:00:00 +0000\nTo: recipient@example.com\nSubject: Test Email"))
        self.assertFalse(
            EmlScanner.match(
                b"Date: Mon, 1 Jan 2024 12:00:00 +0000\nFrom: sender@example.com\nTo: recipient@example.com"))
        # Wrong format
        self.assertFalse(EmlScanner.match(b"This is not an email"))
        self.assertFalse(EmlScanner.match(b"Date: Mon, 1 Jan 2024 12:00:00 +0000\nFrom: sender@example.com"))
