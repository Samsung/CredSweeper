import unittest

from hypothesis import given, strategies

from credsweeper.deep_scanner.dex_scanner import DexScanner, ModifiedUtf8Error


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

    @given(strategies.binary())
    def test_get_deep_scanners_hypothesis_n(self, data):
        try:
            self.assertIsInstance(DexScanner.decode_mutf8(data), bytes)
        except Exception as exc:
            self.assertIsInstance(exc, ModifiedUtf8Error)
