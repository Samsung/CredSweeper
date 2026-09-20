import struct
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
        public_key = b'public key'
        signature = b'signature'
        crx2 = b'Cr24' + struct.pack('<III', 2, len(public_key), len(signature)) + public_key + signature + AZ_DATA
        self.assertEqual(AZ_DATA, CrxScanner.zip_extract(crx2))

        header = b'protobuf header'
        crx3 = b'Cr24' + struct.pack('<II', 3, len(header)) + header + AZ_DATA
        self.assertEqual(AZ_DATA, CrxScanner.zip_extract(crx3))

    def test_zip_extract_n(self):
        # wrong data type
        with self.assertRaises(TypeError):
            self.assertFalse(CrxScanner.zip_extract(None))
        with self.assertRaises(ValueError):
            CrxScanner.zip_extract(b'Cr24' + struct.pack('<II', 3, 1024) + b'truncated')
        with self.assertRaises(ValueError):
            CrxScanner.zip_extract(b'Cr24' + struct.pack('<I', 4) + b'\0' * 24)
