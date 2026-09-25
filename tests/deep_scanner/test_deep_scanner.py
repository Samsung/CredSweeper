import unittest

from hypothesis import given, strategies

from credsweeper.deep_scanner.deep_scanner import DeepScanner
from credsweeper.file_handler.descriptor import Descriptor


class TestDeepScanner(unittest.TestCase):

    def test_get_deep_scanners_static_n(self):
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(None, Descriptor('', '', ''), 0, 0))
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(b'', Descriptor('', '', ''), 0, 0))
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(b'0xFF', Descriptor('', '', ''), 0, 0))

    @given(strategies.binary())
    def test_get_deep_scanners_hypothesis_n(self, data):
        # no exception should be raised
        x, y = DeepScanner.get_deep_scanners(data, Descriptor('', '', ''), 0, 0)
        # no fallback scanners for depth=0
        self.assertListEqual([], y)
