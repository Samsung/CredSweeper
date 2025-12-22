import unittest

from hypothesis import given, strategies

from credsweeper.deep_scanner.strings_scanner import StringsScanner


class TestStringsScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    @given(strategies.binary())
    def test_get_lines_hypothesis_n(self, data):
        self.assertIsNotNone(StringsScanner.get_lines(data))

    def test_get_lines_n(self):
        self.assertListEqual([], StringsScanner.get_lines(b''))
        self.assertListEqual([], StringsScanner.get_lines(b'\x00\xBE'))
        self.assertListEqual([], StringsScanner.get_lines(b'\xF9\x9F\xBEP\xE3\xb4W\xA5:\xF1R\x9C00\xcf\x84t!'))
        self.assertListEqual([], StringsScanner.get_lines(b'\x00\x01\x02PW:R00t\x0D\x00'))

    def test_get_lines_p(self):
        self.assertListEqual([("PW:R00t!", 3)], StringsScanner.get_lines(b'\x00\x01\x02PW:R00t!\x0D\x00'))
        self.assertListEqual([("PW:R00t!", 0)], StringsScanner.get_lines(b'PW:R00t!\x0D\x00'))
        self.assertListEqual([("PW:R00t!", 4)], StringsScanner.get_lines(b'\x00\x01\x02\x03PW:R00t!'))
