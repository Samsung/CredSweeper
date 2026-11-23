import gzip
import random
import sys
import unittest

if (3, 14) <= sys.version_info:
    from compression import zstd
else:
    # todo: remove when Python 3.11, 3.12, 3.13 support ends
    import zstandard as zstd

from credsweeper.common.constants import MAX_LINE_LENGTH, MIN_DATA_LEN
from credsweeper.deep_scanner.zstd_scanner import ZstdScanner, ZstdScannerException
from tests import AZ_DATA

ZSTD_DATA = (b"(\xb5/\xfdd\xcc\x0f\xa5\x01\x00\xb4\x02The quick brown fox jumps over the lazy dog"
             b"\x01\x00\xf3\x04\xd7\xab2\x8a9 =")
ZSTD_FAKE = b"\x28\xB5\x2F\xFD01234567890123456789"
# bytes(range(256)) in a single raw block, the size is declared in the header
ZSTD_TEST = (b"(\xb5/\xfd`\x00\x00\x01\x08\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12"
             b"\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJ"
             b"KLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a"
             b"\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3"
             b"\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc"
             b"\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5"
             b"\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee"
             b"\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

# 200 x 'A' in 10 bytes: a valid frame, but too short for match()
ZSTD_200_A = b"\x28\xB5\x2F\xFD\x20\xC8\x43\x06\x00A"
# 4096 x 'A' in 19 bytes, the size is declared in the header
ZSTD_4096_A = b"(\xb5/\xfd`\x00\x0fM\x00\x00\x10AA\x01\x00\xfb\xf7\x01\x16"
# three frames in a row
ZSTD_3_FRAMES = (b"(\xb5/\xfd x\x9d\x00\x00`first frame\n\x01\x00\xe9iI\x02(\xb5/\xfd \x82\xa5\x00\x00h"
                 b"second frame\n\x01\x00\x12\xd2\xf9\x05(\xb5/\xfd x\x9d\x00\x00`"
                 b"third frame\n\x01\x00\xe9iI\x02")
ZSTD_3_FRAMES_DATA = b"first frame\n" * 10 + b"second frame\n" * 10 + b"third frame\n" * 10


class TestZstdScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_match_n(self):
        self.assertFalse(ZstdScanner.match(random.randbytes(3 * MIN_DATA_LEN)))  # statistical test
        self.assertFalse(ZstdScanner.match(b'\x28\xB5\x2F\xFD'))
        self.assertFalse(ZstdScanner.match(b""))
        self.assertFalse(ZstdScanner.match(b"\x1f\x8b" + b"\0" * 100))  # gzip
        self.assertFalse(ZstdScanner.match(b"\x00" + ZSTD_TEST))  # shifted magic
        self.assertFalse(ZstdScanner.match(b"\x28\xB5\x2F\xFD" + b"\0" * 12))  # 16 bytes
        self.assertFalse(ZstdScanner.match(ZSTD_200_A))  # valid, but too short

    def test_match_p(self):
        self.assertTrue(ZstdScanner.match(b'\x28\xB5\x2F\xFD01234567890123456789'))
        self.assertTrue(ZstdScanner.match(b"(\xb5/\xfd`\xe8\x02M\x00\x00\x10AA\x01\x00\xe3+\x80\x05"))
        self.assertTrue(ZstdScanner.match(b"(\xb5/\xfd \x08A\x00\x00PW:tizen"))
        self.assertTrue(ZstdScanner.match(ZSTD_TEST))
        self.assertTrue(ZstdScanner.match(b"\x28\xB5\x2F\xFD" + b"\0" * 13))  # 17 bytes

    def test_decompress_huge_window_n(self):
        # 10 bytes: no declared size, but the window of 1 GiB is required (window_log=30) and one RLE block of
        # zeroes. A few bytes must not make the decoder allocate gigabytes: it is rejected because of the window,
        # not because of the result size - so it is zstd.ZstdError, but not ZstdScannerException
        data = b"\x28\xB5\x2F\xFD\x00\xA0\x03\x00\x10\x00"
        with self.assertRaises(zstd.ZstdError) as context:
            ZstdScanner.decompress(1_000_000, data)
        self.assertNotIsInstance(context.exception, ZstdScannerException)

    def test_decompress_n(self):
        # the data are valid, but the limit is less than 1 KiB, the minimal window of zstd
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(len(ZSTD_3_FRAMES_DATA), ZSTD_3_FRAMES)
        # any data are over negative test limit
        if (3, 14) <= sys.version_info:
            with self.assertRaises(zstd.ZstdError):
                ZstdScanner.decompress(-1, None)
            self.assertEqual(b'', ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=ZSTD_DATA[:-8]))
        else:
            # todo: remove when Python 3.11, 3.12, 3.13 support ends
            with self.assertRaises(zstd.ZstdError):
                ZstdScanner.decompress(0, b'')
            with self.assertRaises(ZstdScannerException):
                ZstdScanner.decompress(limit=MIN_DATA_LEN, data=ZSTD_DATA[:-8])
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(123456789, ZSTD_FAKE)
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=AZ_DATA)

    def test_decompress_p(self):
        self.assertEqual(AZ_DATA * 100, ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=ZSTD_DATA))
        self.assertEqual(bytes(range(256)), ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=ZSTD_TEST))
        self.assertEqual(b'A' * 200, ZstdScanner.decompress(limit=MAX_LINE_LENGTH, data=ZSTD_200_A))

    def test_decompress_multi_frame_p(self):
        if sys.version_info < (3, 14):
            # todo: remove when Python 3.11, 3.12, 3.13 support ends
            self.assertEqual(ZSTD_3_FRAMES_DATA, ZstdScanner.decompress(1_000_000, ZSTD_3_FRAMES))
        else:
            # 3.14 decompressor extracts the first frame only, the rest of the data is ignored
            self.assertEqual(b"first frame\n" * 10, ZstdScanner.decompress(1_000_000, ZSTD_3_FRAMES))

    def test_decompress_exact_limit_p(self):
        self.assertEqual(b'A' * 4096, ZstdScanner.decompress(4096, ZSTD_4096_A))

    def test_decompress_over_limit_by_one_n(self):
        with self.assertRaises(ZstdScannerException):
            ZstdScanner.decompress(4095, ZSTD_4096_A)

    def test_decompress_declared_size_over_limit_n(self):
        # 64_000_000 of zeroes, the size is declared in the header and it is over the limit
        # gzip is used to keep the static data short
        gzip_zstd_data_64M_00 = (b'\x1f\x8b\x08\x00\x91\xaa\x02k\x02\xff\xd3\xd8\xaa\xff\xb7!\x82a\xc2\x05\xe6\x10\x06'
                                 b'\x06\x01\x06\x06F\x86\xdf\xff-\x0f01\x01\xd9\xa3x\x14\x8f\xe2Q<\x8aG\xf1(\x1e<\x98'
                                 b'\xb9\x81\x85\x01\x00\xd8B\xac\xbb\xb7\x07\x00\x00')
        zstd_data_64M_00 = gzip.decompress(gzip_zstd_data_64M_00)
        if sys.version_info < (3, 14):
            # todo: remove when Python 3.11, 3.12, 3.13 support ends
            self.assertEqual(64_000_000, zstd.frame_content_size(zstd_data_64M_00))
        with self.assertRaises(ZstdScannerException if sys.version_info < (3, 14) else zstd.ZstdError):
            ZstdScanner.decompress(1_000_000, zstd_data_64M_00)

    def test_decompress_unknown_size_over_limit_n(self):
        # 64_000_000 of zeroes, the size is NOT declared in the header: the window is over the limit
        gzip_zstd_64M_00_nosize = (b'\x1f\x8b\x08\x007\xa7\x02k\x02\xff\xd3\xd8\xaa\xff\x97!"\x84\x81A\x80\x81\x81\x91'
                                   b'\xe1\xf7\x7f\xcb\x03LL@\xf6(\x1e\xc5\xa3x\x14\x8f\xe2Q<\x8a\x07\x0ffn`a\x00\x00'
                                   b'\x9a\xb8\xb7y\xb3\x07\x00\x00')
        zstd_data = gzip.decompress(gzip_zstd_64M_00_nosize)
        if sys.version_info < (3, 14):
            # todo: remove when Python 3.11, 3.12, 3.13 support ends
            self.assertEqual(-1, zstd.frame_content_size(zstd_data))
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(1_000_000, zstd_data)

    def test_decompress_multi_frame_sum_over_limit_n(self):
        # each frame is under the limit (first frame passes a header check), the sum is over
        frame = (b'(\xb5/\xfd\xa0\x00`\t\x00L\x00\x00\x08\x00\x01\x00\xfc\xff\xe4'
                 b'N\x08\x02\x00\x10\x00\x02\x00\x10\x00\x02\x00\x10\x00\x03\x00\x0b\x00')
        data = frame * 4  # 4 x 600 KiB = 2.4 MB in total
        if sys.version_info < (3, 14):
            # todo: remove when Python 3.11, 3.12, 3.13 support ends
            self.assertEqual(600 * 1024, zstd.frame_content_size(data))
            with self.assertRaises(ZstdScannerException):
                ZstdScanner.decompress(1_000_000, data)
        else:
            # todo: remove when Python 3.11, 3.12, 3.13 support ends
            # 3.14 decompressor extracts the first frame only: the sum is not checked
            self.assertEqual(600 * 1024, len(ZstdScanner.decompress(1_000_000, data)))

    def test_decompress_unknown_size_2M_over_limit_n(self):
        # 2_000_000 bytes of zeroes, the size is not declared, the limit is 1_000_000
        gzip_zstd_2M_00 = (b'\x1f\x8b\x08\x00c\xa5\x02k\x02\xff\xd3\xd8\xaa\xff\x97!"\x84\x81A\x80\x81\x81\x91\xe1\xf7'
                           b'\x7f\xcb\x03LL@\xf6(\x1e\xc5\xa3x\x14\x8f\xe2Q<\x8a\x07\x0ffn`a\x00\x00\x9a\xb8\xb7y\xb3'
                           b'\x07\x00\x00')
        zstd_data = gzip.decompress(gzip_zstd_2M_00)
        with self.assertRaises(zstd.ZstdError):
            ZstdScanner.decompress(1_000_000, zstd_data)
