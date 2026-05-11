import unittest

from credsweeper.deep_scanner.crx_scanner import CrxScanner
from tests import AZ_DATA


class TestCrxScanner(unittest.TestCase):

    def test_match_p(self):
        self.assertTrue(CrxScanner.match(b'Cr24\x02\x00\x00\x00' + b'\0' * 32))
        self.assertTrue(CrxScanner.match(b'Cr24\x03\x00\x00\x00' + b'\0' * 32))

    def test_match_n(self):
        # wrong data type
        with self.assertRaises(AttributeError):
            self.assertFalse(CrxScanner.match(None))
        with self.assertRaises(AttributeError):
            self.assertFalse(CrxScanner.match(1))
        # few bytes than required
        self.assertFalse(CrxScanner.match(b'Cr24\x02\x00\x00\x00' + b'\0' * 16))
        self.assertFalse(CrxScanner.match(AZ_DATA))

    def test_zip_extract_p(self):
        self.assertEqual(b'', CrxScanner.zip_extract(b'\0' * 16))
        self.assertEqual(AZ_DATA, CrxScanner.zip_extract(b'\0' * 16 + AZ_DATA))

    def test_zip_extract_n(self):
        # wrong data type
        with self.assertRaises(TypeError):
            self.assertFalse(CrxScanner.zip_extract(None))
