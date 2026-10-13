import unittest
from unittest.mock import MagicMock

from credsweeper.utils.html_extractor import HtmlExtractor
from tests import SAMPLE_HTML


class TestHtmlExtractor(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_extract_n(self):
        text = ''
        result = HtmlExtractor().extract(text, 3, 1000, MagicMock())
        self.assertListEqual([], result[0])
        self.assertListEqual([], result[1])
        self.assertEqual(0, result[2])

    def test_extract_p(self):
        text = SAMPLE_HTML.read_text()
        result = HtmlExtractor().extract(text, 3, 1000, MagicMock())
        # lines and lines numbers
        self.assertEqual(len(result[0]), len(result[1]))
        self.assertEqual(608, result[2])
