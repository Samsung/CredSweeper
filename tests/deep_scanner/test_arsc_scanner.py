import random
import unittest

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.deep_scanner.arsc_scanner import ArscScanner
from .. import SAMPLE_ARSC


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
        self.assertTrue(ArscScanner.match(SAMPLE_ARSC.read_bytes()))
        self.assertTrue(ArscScanner.match(b"\x02\x00\x0C\x00\x0D\x00\x00\x000123456789abcdef"))

    def test_walk_arsc_n(self):
        data = bytearray(b"\x02\x00\x0C\x00")
        data.extend(random.randbytes(random.randint(100, 1000)))
        with self.assertRaises(Exception, msg=repr(data)):
            list(ArscScanner.walk_arsc(data))

    def test_walk_arsc_p(self):
        result = list(ArscScanner.walk_arsc(SAMPLE_ARSC.read_bytes()))
        self.assertEqual(9, len(result))
