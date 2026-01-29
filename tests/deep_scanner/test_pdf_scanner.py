import unittest

from credsweeper.deep_scanner.pdf_scanner import PdfScanner


class TestPdfScanner(unittest.TestCase):

    def test_match_p(self):
        self.assertTrue(PdfScanner.match(b'\x25\x50\x44\x46\x2D'))
        self.assertTrue(PdfScanner.match(b'%PDF-!'))

    def test_match_n(self):
        self.assertFalse(PdfScanner.match(None))
        self.assertFalse(PdfScanner.match(b''))
        self.assertFalse(PdfScanner.match(b'%PDF+'))
