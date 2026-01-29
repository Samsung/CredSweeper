import unittest

from credsweeper.deep_scanner.gzip_scanner import GzipScanner


class TestGzipScanner(unittest.TestCase):

    def test_match_p(self):
        self.assertTrue(GzipScanner.match(b'\x1f\x8b\x08'))
        self.assertTrue(GzipScanner.match(b'\x1f\x8b\x08xxx'))

    def test_match_n(self):
        self.assertFalse(GzipScanner.match(None))
        self.assertFalse(GzipScanner.match(b'\x1f'))
        self.assertFalse(GzipScanner.match(b'\x1f\x8bxxx'))
        self.assertFalse(GzipScanner.match(b'\x1f\x8b\x02'))
