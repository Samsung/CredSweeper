import random
import unittest
from compression import zstd

from credsweeper.common.constants import MAX_LINE_LENGTH, MIN_DATA_LEN
from credsweeper.deep_scanner.zstd_scanner import ZstdScanner
from tests import AZ_DATA

ZSTD_DATA = b'(\xb5/\xfdd\xcc\x0f\xa5\x01\x00\xb4\x02The quick brown fox jumps over the lazy dog\x01\x00\xf3\x04\xd7\xab2\x8a9 ='
ZSTD_FAKE = b"\x28\xB5\x2F\xFD01234567890123456789"


class TestZstdScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_match_n(self):
        self.assertFalse(ZstdScanner.match(random.randbytes(3 * MIN_DATA_LEN)))
        self.assertFalse(ZstdScanner.match(b'\x28\xB5\x2F\xFD'))

    def test_match_p(self):
        self.assertTrue(ZstdScanner.match(b'\x28\xB5\x2F\xFD01234567890123456789'))

    def test_decompress_n(self):
        # any data are over negative test limit
        self.assertIsNone(ZstdScanner.decompress(-1, None))
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(123456789, ZSTD_FAKE)
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=AZ_DATA)
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=AZ_DATA)
        self.assertEqual(b'', ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=ZSTD_DATA[:-8]))

    def test_decompress_p(self):
        self.assertEqual(AZ_DATA * 100, ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=ZSTD_DATA))
