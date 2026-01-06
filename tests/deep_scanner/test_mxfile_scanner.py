import unittest

from credsweeper.deep_scanner.mxfile_scanner import MxfileScanner


class TestMxfileScanner(unittest.TestCase):

    def test_match_n(self):
        self.assertFalse(MxfileScanner.match(b"<mxfile>"))
        self.assertFalse(MxfileScanner.match(b"</mxfile><mxfile>"))
        with self.assertRaises(AttributeError):
            MxfileScanner.match(None)
        with self.assertRaises(AttributeError):
            MxfileScanner.match(1)

    def test_match_p(self):
        self.assertTrue(MxfileScanner.match(b"<mxfile atr=0><table></table></mxfile>"))
