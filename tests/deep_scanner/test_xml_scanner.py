import unittest

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.deep_scanner.xml_scanner import XmlScanner


class TestXmlScanner(unittest.TestCase):

    def test_match_n(self):
        with self.assertRaises(TypeError):
            XmlScanner.match(None)
        self.assertFalse(XmlScanner.match(b''))
        self.assertFalse(XmlScanner.match(b"!<>"))
        self.assertFalse(XmlScanner.match(b"</onlyClosingTagIsFail>"))
        self.assertFalse(XmlScanner.match(b"</p><p>"))
        self.assertFalse(XmlScanner.match(b"<br />"))
        self.assertFalse(
            XmlScanner.match(bytearray(b'\n' * MAX_LINE_LENGTH) + bytearray(b"    <xml>far far away</xml>")))
        self.assertFalse(XmlScanner.match(b"<html> unmatched tags </xml>"))
        self.assertFalse(XmlScanner.match(b"<?xml version='1.0' encoding='utf-8'?>"))

    def test_match_p(self):
        self.assertTrue(XmlScanner.match(b"<?xml version='1.0' encoding='utf-8'?><xml> matched tags </xml>"))
        self.assertTrue(XmlScanner.match(b"<mxfile atr=0><table></table></mxfile>"))
        self.assertTrue(
            XmlScanner.match(
                bytearray(b'\n<xml> far far away ') + bytearray(b'\n' * MAX_LINE_LENGTH) +
                bytearray(b' long long ago </xml>')))
