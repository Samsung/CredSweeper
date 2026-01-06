import unittest

from credsweeper.deep_scanner.html_scanner import HtmlScanner


class TestHtmlScanner(unittest.TestCase):

    def test_match_n(self):
        self.assertFalse(HtmlScanner.match(b"</html><html>"))
        with self.assertRaises(AttributeError):
            HtmlScanner.match(None)

    def test_match_p(self):
        self.assertTrue(HtmlScanner.match(b"<mxfile atr=0><table></table></mxfile>"))
