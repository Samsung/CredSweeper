import unittest

from hypothesis import given, strategies

from credsweeper import DataContentProvider
from credsweeper.common.constants import MAX_LINE_LENGTH, CHUNK_SIZE, MIN_DATA_LEN
from credsweeper.deep_scanner.deep_scanner import DeepScanner
from credsweeper.deep_scanner.strings_scanner import StringsScanner
from credsweeper.deep_scanner.text_scanner import TextScanner
from credsweeper.deep_scanner.zip_scanner import ZipScanner
from tests import SAMPLE_ZIP, AZ_DATA


class TestDeepScanner(unittest.TestCase):

    def test_get_deep_scanners_static_n(self):
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(DataContentProvider(None), 1, MAX_LINE_LENGTH))
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(DataContentProvider(b''), 1, MAX_LINE_LENGTH))
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(DataContentProvider(b'\xFF'), 1, MAX_LINE_LENGTH))
        self.assertEqual(([], [StringsScanner]),
                         DeepScanner.get_deep_scanners(DataContentProvider(SAMPLE_ZIP.read_bytes()), 1, MIN_DATA_LEN))

    def test_get_deep_scanners_static_p(self):
        self.assertEqual(([TextScanner], []),
                         DeepScanner.get_deep_scanners(DataContentProvider(AZ_DATA), 1, MAX_LINE_LENGTH))
        self.assertEqual(
            ([StringsScanner], []),
            DeepScanner.get_deep_scanners(DataContentProvider(b'\xe47\x00\x00@7\x00\x00\x01\x00\x02\x00\x00\x00\x00'),
                                          1, MAX_LINE_LENGTH))
        self.assertEqual(([ZipScanner], [StringsScanner]),
                         DeepScanner.get_deep_scanners(DataContentProvider(SAMPLE_ZIP.read_bytes()), 1,
                                                       MAX_LINE_LENGTH))

    @given(  #
        strategies.integers(min_value=-1, max_value=MAX_LINE_LENGTH),  #
        strategies.integers(min_value=-2, max_value=3),  #
        strategies.binary(min_size=0, max_size=CHUNK_SIZE),  #
    )
    def test_get_deep_scanners_hypothesis_n(self, data, depth, limit):
        # no exception should be raised
        self.assertTrue(DeepScanner.get_deep_scanners(DataContentProvider(data), depth, limit))
