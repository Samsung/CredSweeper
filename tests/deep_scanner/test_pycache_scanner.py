import sys
import unittest

from credsweeper.common.constants import RECURSIVE_SCAN_LIMITATION
from credsweeper.deep_scanner.pycache_scanner import PycacheScanner, SLOT_SIZE
from tests import AZ_DATA, SAMPLE_PYC


class TestPycacheScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_constant_p(self):
        self.assertEqual(SLOT_SIZE, sys.getsizeof(42) + (sys.getsizeof([None]) - sys.getsizeof([])))

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

    def test_match_p(self):
        # Valid pyc archive signature
        self.assertTrue(PycacheScanner.match(b"!!\r\n\x00\0\0\0abcdefghijklmnopqrstuvwxyz"))
        self.assertTrue(PycacheScanner.match(b"!!\r\n\x01\0\0\0abcdefghijklmnopqrstuvwxyz"))
        self.assertTrue(PycacheScanner.match(b"!!\r\n\x03\0\0\0abcdefghijklmnopqrstuvwxyz"))
        with open(SAMPLE_PYC, "rb") as f:
            data = f.read()
        self.assertTrue(PycacheScanner.match(data))

    def test_walk_pycache_p(self):
        with open(SAMPLE_PYC, "rb") as f:
            data = f.read()
        self.assertEqual(25, len(list(PycacheScanner.walk_pycache(data, RECURSIVE_SCAN_LIMITATION))))
