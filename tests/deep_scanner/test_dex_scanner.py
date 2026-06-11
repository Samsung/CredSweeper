import unittest

from credsweeper.deep_scanner.dex_scanner import DexScanner


class TestDexScanner(unittest.TestCase):

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            DexScanner.match(None)
        with self.assertRaises(AttributeError):
            DexScanner.match(1)
        # Too short
        self.assertFalse(DexScanner.match(b""))
        self.assertFalse(DexScanner.match(b"X3"))
        # Wrong signature
        self.assertFalse(DexScanner.match(b"dex\n030\0"))
        self.assertFalse(DexScanner.match(b"dex\r037\0"))

    def test_match_p(self):
        self.assertTrue(DexScanner.match(b"dex\n035\0"))
        self.assertTrue(DexScanner.match(b"dey\n039\0"))
