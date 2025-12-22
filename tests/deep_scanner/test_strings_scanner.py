import unittest

from hypothesis import given, strategies

from credsweeper.deep_scanner.strings_scanner import StringsScanner


class TestStringsScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    @given(strategies.binary())
    def test_get_lines_hypothesis_n(self, data):
        self.assertIsNotNone(StringsScanner.get_enumerated_lines(data))

    def test_get_lines_n(self):
        self.assertListEqual([], StringsScanner.get_enumerated_lines(b''))
        self.assertListEqual([], StringsScanner.get_enumerated_lines(b'\x00\xBE'))
        self.assertListEqual([], StringsScanner.get_enumerated_lines(b'\x9F\xBEP\xE3\xb4W\xA5:\xF1R\x9C00\xcf\x84t!'))
        self.assertListEqual([], StringsScanner.get_enumerated_lines(b'\x00\x01\x02PW:R00t\x0D\x00'))

    def test_get_lines_p(self):
        self.assertListEqual([(3, "PW:R00t!")], StringsScanner.get_enumerated_lines(b'\x00\x01\x02PW:R00t!\x0D\x00'))
        self.assertListEqual([(0, "PW:R00t!")], StringsScanner.get_enumerated_lines(b'PW:R00t!\x0D\x00'))
        self.assertListEqual([(4, "PW:R00t!")], StringsScanner.get_enumerated_lines(b'\x00\x01\x02\x03PW:R00t!'))
        self.assertListEqual(
            [(9, 'Salt:CwXD\t3dsd'), (24, 'Token:SOMETEST')],
            StringsScanner.get_enumerated_lines(b'\x9F\xBEP\xE3\xb4W\xA5:\xFFSalt:CwXD\x093dsd\nToken:SOMETEST\0'))
