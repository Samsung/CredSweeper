import random
import unittest
from pathlib import Path

from credsweeper.app import APP_PATH
from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.deep_scanner.arsc_scanner import ArscScanner


class TestArscScanner(unittest.TestCase):

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            ArscScanner.match(None)
        with self.assertRaises(AttributeError):
            ArscScanner.match(1)
        # Too short
        self.assertFalse(ArscScanner.match(b"\x02\x00\x0C\x00"))
        self.assertFalse(ArscScanner.match(b"\x02\x00\x0C\x00\x00\x00\x00\x00"))
        # Wrong size
        self.assertFalse(ArscScanner.match(b"\x02\x00\x0C\x00\x00\x00\x00\x00!"))
        # Wrong signature
        random_bytes = random.randbytes(MIN_DATA_LEN)
        self.assertFalse(ArscScanner.match(random_bytes))

    def test_match_p(self):
        self.assertTrue(ArscScanner.match(b"\x02\x00\x0C\x00\x0C\x00\x00\x001234"))
        src = APP_PATH.parent / "resources-big.arsc"
        # Valid Arsc archive signature
        self.assertTrue(ArscScanner.match(src.read_bytes()))
