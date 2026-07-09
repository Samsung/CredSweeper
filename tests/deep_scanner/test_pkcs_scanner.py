import unittest

from credsweeper.deep_scanner.pkcs_scanner import PkcsScanner
from tests import SAMPLES_PATH


class TestPkcsScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_match_n(self):
        with self.assertRaises(TypeError):
            self.assertFalse(PkcsScanner.match(None))
        self.assertFalse(PkcsScanner.match(b''))
        self.assertFalse(PkcsScanner.match(b'0' * 256))
        # too small - pkcs size is 8 by algo
        self.assertFalse(PkcsScanner.match(b"0\x80abcd\000\000"))

    def test_match_p(self):
        self.assertTrue(PkcsScanner.match((SAMPLES_PATH / "pkcs12.changeme.p12").read_bytes()))
