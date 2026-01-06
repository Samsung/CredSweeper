import unittest

from credsweeper.deep_scanner.tmx_scanner import TmxScanner


class TestTmxScanner(unittest.TestCase):

    def test_match_p(self):
        # Valid TMX format with ThreatModel tags
        tmx_data = b"<ThreatModel>Some content</ThreatModel>"
        self.assertTrue(TmxScanner.match(tmx_data))

        # Valid TMX format with KnowledgeBase tags
        tmx_data2 = b"<KnowledgeBase>Some content</KnowledgeBase>"
        self.assertTrue(TmxScanner.match(tmx_data2))

        # TMX format with additional content
        tmx_data3 = b"Some prefix <ThreatModel>content</ThreatModel> some suffix"
        self.assertTrue(TmxScanner.match(tmx_data3))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            TmxScanner.match(None)
        with self.assertRaises(AttributeError):
            TmxScanner.match(1)
        # Missing or incomplete tags
        self.assertFalse(TmxScanner.match(b"<ThreatModel>"))
        self.assertFalse(TmxScanner.match(b"</ThreatModel>"))
        self.assertFalse(TmxScanner.match(b"<KnowledgeBase>"))
        self.assertFalse(TmxScanner.match(b"</KnowledgeBase>"))
        # Wrong order
        self.assertFalse(TmxScanner.match(b"</ThreatModel><ThreatModel>"))
        self.assertFalse(TmxScanner.match(b"</KnowledgeBase><KnowledgeBase>"))
        # Different tags
        self.assertFalse(TmxScanner.match(b"<OtherTag>content</OtherTag>"))
        self.assertFalse(TmxScanner.match(b"<xml>content</xml>"))
