import contextlib
import itertools
import random
import sys
import unittest
import zlib

import pytest
from hypothesis import given, strategies

from credsweeper.common.constants import MAX_LINE_LENGTH, CHUNK_SIZE, CHUNK_STEP_SIZE
from credsweeper.deep_scanner.zlib_scanner import ZlibScanner


class TestZlibScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    @given(strategies.binary())
    def test_match_hypothesis_n(self, data):
        # too hard to find random data which looks like zlib compressed data
        self.assertFalse(ZlibScanner.match(data))

    def test_match_p(self):
        d = zlib.decompress(b'x\x9c3K\xb14NN\xb3H\xd35LL1\xd7MIML\xd1MJMM\xd35\xb10ON1LN\xb400M\x03\x00\xc8Y\n\xd1')
        self.assertTrue(
            ZlibScanner.match(b'x\x9c3K\xb14NN\xb3H\xd35LL1\xd7MIML\xd1MJMM\xd35\xb10ON1LN\xb400M\x03\x00\xc8Y\n\xd1'))
        d = ZlibScanner.decompress(
            100000, b'x\x9c3K\xb14NN\xb3H\xd35LL1\xd7MIML\xd1MJMM\xd35\xb10ON1LN\xb400M\x03\x00\xc8Y\n\xd1')
        self.assertTrue(ZlibScanner.match(b"XG5FAKE"))

    @given(strategies.binary())
    def test_decompress_hypothesis_n(self, data):
        # any data are over negative test limit
        with self.assertRaises(Exception):
            ZlibScanner.decompress(-1, data)

    # todo: fix when python 3.10 support ends
    @pytest.mark.skipif(10 == sys.version_info.minor, reason="zlib.compress was changed in 3.11")
    def test_decompress_n(self):
        self.assertTrue(CHUNK_STEP_SIZE < CHUNK_SIZE < MAX_LINE_LENGTH)
        total_counter = check_counter = 0
        for level, wbits in itertools.product(list(range(10)), list(range(8, 32))):
            total_counter += 1
            data = random.randbytes(random.randint(CHUNK_SIZE, MAX_LINE_LENGTH))
            try:
                # check combinations which are valid
                zlib_data = zlib.compress(data, level=level, wbits=wbits)
            except zlib.error:
                continue
            with self.assertRaises((ValueError, zlib.error)):
                check_counter += 1
                ZlibScanner.decompress(CHUNK_STEP_SIZE, zlib_data)
        self.assertTrue(100 < check_counter < total_counter)

    # todo: fix when python 3.10 support ends
    @pytest.mark.skipif(10 == sys.version_info.minor, reason="zlib.compress was changed in 3.11")
    def test_decompress_p(self):
        total_counter = check_counter = 0
        for level, wbits in itertools.product(list(range(10)), list(range(8, 32))):
            total_counter += 1
            data = random.randbytes(random.randint(0, MAX_LINE_LENGTH))
            with contextlib.suppress(zlib.error):
                # check combinations which are valid
                zlib_data = zlib.compress(data, level=level, wbits=wbits)
                self.assertEqual(data, ZlibScanner.decompress(MAX_LINE_LENGTH, zlib_data), str((level, wbits)))
                self.assertTrue(ZlibScanner.match(zlib_data))
                check_counter += 1
        self.assertTrue(10 < check_counter < total_counter)
