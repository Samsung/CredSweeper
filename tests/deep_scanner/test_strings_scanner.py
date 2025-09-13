import unittest

from hypothesis import given, strategies

from credsweeper.deep_scanner.strings_scanner import StringsScanner


class TestDebScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    @given(strategies.binary())
    def test_get_shannon_entropy_hypothesis_n(self, data):
        self.assertIsNotNone(StringsScanner.get_strings(data))
