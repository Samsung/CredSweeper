import unittest
import zlib

from hypothesis import given, strategies

from credsweeper.deep_scanner.zlib_scanner import ZlibScanner


class TestZlibScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    @given(strategies.binary())
    def test_possible_zlib_hypothesis_n(self, data):
        # too hard to find random data which looks like zlib compressed data
        self.assertFalse(ZlibScanner.possible_zlib(data))

    @given(strategies.binary())
    def test_possible_zlib_hypothesis_p(self, data):
        self.assertTrue(ZlibScanner.possible_zlib(zlib.compress(data)))
