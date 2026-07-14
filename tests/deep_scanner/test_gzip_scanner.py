import unittest

from credsweeper.deep_scanner.gzip_scanner import GzipScanner


class TestGzipScanner(unittest.TestCase):

    def test_match_p(self):
        self.assertTrue(GzipScanner.match(b'\x1f\x8b\x08'))
        self.assertTrue(GzipScanner.match(b'\x1f\x8b\x08xxx'))

    def test_match_n(self):
        with self.assertRaises(AttributeError):
            self.assertFalse(GzipScanner.match(None))
        self.assertFalse(GzipScanner.match(b'\x1f\x8b\x00'))
        self.assertFalse(GzipScanner.match(b'\x2f\x8b\x01'))
