import unittest

from credsweeper.deep_scanner.pycache_scanner import PycacheScanner
from tests import AZ_DATA


class TestPycacheScanner(unittest.TestCase):

    def test_match_p(self):
        # Valid pyc archive signature
        self.assertTrue(PycacheScanner.match(b"!!\r\n\x00\0\0\0abcdefghijklmnopqrstuvwxyz"))
        self.assertTrue(PycacheScanner.match(b"!!\r\n\x01\0\0\0abcdefghijklmnopqrstuvwxyz"))
        self.assertTrue(PycacheScanner.match(b"!!\r\n\x03\0\0\0abcdefghijklmnopqrstuvwxyz"))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(TypeError):
            PycacheScanner.match(None)
        with self.assertRaises(TypeError):
            PycacheScanner.match(1)
        # Too short
        self.assertFalse(PycacheScanner.match(b""))
        # Wrong signature
        self.assertFalse(PycacheScanner.match(AZ_DATA))
