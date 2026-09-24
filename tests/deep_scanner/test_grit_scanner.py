import unittest
from pathlib import Path

from credsweeper.deep_scanner.grit_scanner import GritScanner
from tests import SAMPLES_PATH


class TestGritScanner(unittest.TestCase):

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            GritScanner.match(None)
        with self.assertRaises(AttributeError):
            GritScanner.match(1)
        # Too short
        self.assertFalse(GritScanner.match(b""))
        self.assertFalse(GritScanner.match(b"X3"))
        # Wrong signature
        self.assertFalse(GritScanner.match(b"\x01\x00\x00\x00"))

    def test_match_p(self):
        self.assertTrue(GritScanner.match(b"\x04\x00\x00\x00"))
        self.assertTrue(GritScanner.match(b"\x05\x00\x00\x00"))

    def test_walk_n(self):
        data = bytearray(b'\0' * 1000)
        data[0] = 4
        self.assertEqual(0, len(list(GritScanner.walk_pak(data, 1 << 32))))

    def test_walk_p(self):
        data = Path(SAMPLES_PATH / "sample.pak").read_bytes()
        self.assertEqual(1, len(list(GritScanner.walk_pak(data, 1 << 32))))
