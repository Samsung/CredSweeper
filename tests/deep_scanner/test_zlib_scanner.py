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
from tests import AZ_DATA

ZLIB_DATA = zlib.compress(AZ_DATA)


class TestZlibScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    @given(strategies.binary())
    def test_match_hypothesis_n(self, data):
        # too hard to find random data which looks like zlib compressed data
        self.assertFalse(ZlibScanner.match(data))

    def test_match_p(self):
        self.assertTrue(ZlibScanner.match(ZLIB_DATA))
        self.assertTrue(ZlibScanner.match(b"XG5FAKE"))

    @given(strategies.binary())
    def test_decompress_hypothesis_n(self, data):
        # any data are over negative test limit
        with self.assertRaises(Exception):
            ZlibScanner.decompress(-1, data)

    def test_decompress_static_n(self):
        with self.assertRaises(zlib.error):
            ZlibScanner.decompress(limit=MAX_LINE_LENGTH, data=AZ_DATA)
        with self.assertRaises(ValueError):
            ZlibScanner.decompress(limit=MAX_LINE_LENGTH, data=ZLIB_DATA + AZ_DATA)
        with self.assertRaises(ValueError):
            ZlibScanner.decompress(limit=10, data=b"XG5FAKE")
        with self.assertRaises(ValueError):
            ZlibScanner.decompress(limit=MAX_LINE_LENGTH, data=ZLIB_DATA[:-1])
        with self.assertRaises(ValueError):
            ZlibScanner.decompress(limit=1, data=ZLIB_DATA)

    def test_decompress_static_p(self):
        self.assertEqual(AZ_DATA, ZlibScanner.decompress(limit=MAX_LINE_LENGTH, data=ZLIB_DATA))

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
