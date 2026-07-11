import unittest

from credsweeper.deep_scanner.snk_scanner import SnkScanner


class TestSnkScanner(unittest.TestCase):

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            SnkScanner.match(None)
        with self.assertRaises(AttributeError):
            SnkScanner.match(1)
        # Too short
        self.assertFalse(SnkScanner.match(b""))
        self.assertFalse(SnkScanner.match(b"\x07\x02\x00\x00\x00$\x00\x00RSA1"))

    def test_match_p(self):
        # Valid Java KeyStore signature
        self.assertTrue(SnkScanner.match(b"\x07\x02\x00\x00\x00$\x00\x00RSA2\x00\x04\x00\x00"))
