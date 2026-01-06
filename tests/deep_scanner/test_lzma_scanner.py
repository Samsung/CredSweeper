import unittest

from credsweeper.deep_scanner.lzma_scanner import LzmaScanner


class TestLzmaScanner(unittest.TestCase):

    def test_match_p(self):
        # Valid LZMA signature (XZ format)
        self.assertTrue(LzmaScanner.match(b"\xFD7zXZ\x00"))
        # Valid LZMA signature (legacy format)
        self.assertTrue(LzmaScanner.match(b"\x5D\x00\x00"))
        self.assertTrue(LzmaScanner.match(b"\xFD7zXZ\x00\x00\x00\x00\x00"))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            LzmaScanner.match(None)
        with self.assertRaises(AttributeError):
            LzmaScanner.match(1)
        # Too short
        self.assertFalse(LzmaScanner.match(b""))
        self.assertFalse(LzmaScanner.match(b"\x5D\x00"))
        # Wrong signature
        self.assertFalse(LzmaScanner.match(b"\xFD7zXY\x00"))
        self.assertFalse(LzmaScanner.match(b"\x5D\x00\x01"))
        self.assertFalse(LzmaScanner.match(b"\xFE7zXZ\x00"))
