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

    def test_is_media_patterns_p(self):
        n = m = 0
        for k, v in DeepScanner.MEDIA_PATTERNS.items():
            m += 1
            for i in v:
                self.assertEqual(k, i[0][0], (k, v))
                n += 1
        self.assertTrue(0 < m < n, (m, n))
