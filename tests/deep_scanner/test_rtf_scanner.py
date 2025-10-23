import unittest

from credsweeper.deep_scanner.rtf_scanner import RtfScanner

SIMPLE_SAMPLE = rb"""{\rtf1\ansi\deff3\adeflang1025
{\dbch
\u48708\'3f\u48128\'3f\u48264\'3f\u54840\'3f}{\loch
:pR5!Db@}
\par }"""


class TestRtfScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_get_lines_n(self):
        self.assertListEqual([''], RtfScanner.get_lines(r"{\rtf1}"))

    def test_get_lines_p(self):
        self.assertListEqual(['비밀번호:pR5!Db@', ''], RtfScanner.get_lines(SIMPLE_SAMPLE.decode()))
