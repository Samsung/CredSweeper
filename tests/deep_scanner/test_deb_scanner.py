import unittest

from credsweeper.deep_scanner.deb_scanner import DebScanner


class TestDebScanner(unittest.TestCase):

    def test_match_p(self):
        # Valid deb archive signature
        self.assertTrue(DebScanner.match(b"!<arch>\n"))
        self.assertTrue(DebScanner.match(b"!<arch>\nmore data here"))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            DebScanner.match(None)
        with self.assertRaises(AttributeError):
            DebScanner.match(1)
        # Too short
        self.assertFalse(DebScanner.match(b""))
        self.assertFalse(DebScanner.match(b"!<arch>"))
        # Wrong signature
        self.assertFalse(DebScanner.match(b"<arch>\n"))
        self.assertFalse(DebScanner.match(b"!<arch>"))
        self.assertFalse(DebScanner.match(b"!<arch>\r"))
