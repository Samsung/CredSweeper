import base64
import unittest
import zlib

from credsweeper.deep_scanner.tar_scanner import TarScanner


class TestTarScanner(unittest.TestCase):

    def test_match_p(self):
        # there is 10240 bytes of simple tar file
        tar_zlib_base64 = (b"eJztzzEOwjAQBMCreYWfYIfEfk9eEMmY/2NRUoAoIoQ002xxW+yNvcfZ8lTr+szpNac1ylaWVuqWW41c8tKukfLpy6"
                           b"b7bew9pejHMd71Pt3/1Hz+8usNAAAAAAAAAAAAfO8BVeUSWg==")
        # there is a tar file with single file and without compression
        data = zlib.decompress(base64.b64decode(tar_zlib_base64))
        self.assertTrue(TarScanner.match(data))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(TypeError):
            TarScanner.match(None)
        with self.assertRaises(TypeError):
            TarScanner.match(1)
        # Too short
        self.assertFalse(TarScanner.match(b""))
        self.assertFalse(TarScanner.match(b"\x00" * 100))
        # Wrong magic
        tar_data = b"\x00" * 512
        tar_data = tar_data[:257] + b"wrong!" + tar_data[263:]
        self.assertFalse(TarScanner.match(tar_data))
