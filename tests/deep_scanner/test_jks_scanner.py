import unittest

from credsweeper.deep_scanner.jks_scanner import JksScanner


class TestJksScanner(unittest.TestCase):

    def test_match_p(self):
        # Valid Java KeyStore signature
        self.assertTrue(JksScanner.match(b"\xFE\xED\xFE\xED"))
        self.assertTrue(JksScanner.match(b"\xFE\xED\xFE\xED\x00\x00"))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            JksScanner.match(None)
        with self.assertRaises(AttributeError):
            JksScanner.match(1)
        # Too short
        self.assertFalse(JksScanner.match(b""))
        self.assertFalse(JksScanner.match(b"\xFE\xED\xFE"))
        # Wrong signature
        self.assertFalse(JksScanner.match(b"\xFE\xED\xFE\xEF"))
        self.assertFalse(JksScanner.match(b"\xED\xFE\xED\xFE"))
