import unittest

from credsweeper.deep_scanner.zip_scanner import ZipScanner
from tests import AZ_DATA


class TestZipScanner(unittest.TestCase):

    def test_match_p(self):
        self.assertTrue(ZipScanner.match(b'PK\003\004'))
        # empty archive - no files
        self.assertTrue(ZipScanner.match(b'PK\x05\x06\x00\x00'))
        # not supported spanned archive (multi volume)
        self.assertFalse(ZipScanner.match(b'PK\x07\x08'))

    def test_match_n(self):
        # wrong data type
        self.assertFalse(ZipScanner.match(None))
        self.assertFalse(ZipScanner.match(1))
        # few bytes than required
        self.assertFalse(ZipScanner.match(b''))
        self.assertFalse(ZipScanner.match(b'P'))
        self.assertFalse(ZipScanner.match(b'PK'))
        self.assertFalse(ZipScanner.match(b'PK\003'))
        # wrong signature
        self.assertFalse(ZipScanner.match(b'PK\003\003'))
        # plain text data
        self.assertFalse(ZipScanner.match(AZ_DATA))
