import math
import unittest
from unittest.mock import MagicMock

import pytest

from credsweeper.config.config import Config
from credsweeper.filters import ValueMorphemesCheck
from tests import AZ_STRING
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueMorphemesCheck(unittest.TestCase):

    def setUp(self) -> None:
        self.config = MagicMock(spec=Config)

    def test_min_patter_len_n(self) -> None:
        with self.assertRaises(ValueError):
            ValueMorphemesCheck(self.config, -1)

    def test_init_n(self) -> None:
        test_filter = ValueMorphemesCheck(self.config)
        self.assertListEqual([1, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8], test_filter.thresholds)

    def test_init_p(self) -> None:
        test_filter = ValueMorphemesCheck(self.config, 7)
        self.assertListEqual([7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7], test_filter.thresholds)

    def test_run_small_n(self) -> None:
        line_data = get_line_data(self.config, file_path="file_path", line='*', pattern=LINE_VALUE_PATTERN)
        self.assertFalse(ValueMorphemesCheck().run(line_data, DUMMY_ANALYSIS_TARGET))

    def test_run_oversize_n(self) -> None:
        line_data = get_line_data(self.config, file_path="file_path", line='*', pattern=LINE_VALUE_PATTERN)
        line_data.value = '*' * (2**16)
        value_morpheme_check = ValueMorphemesCheck()
        self.assertGreater(len(line_data.value).bit_length(), len(value_morpheme_check.thresholds))
        self.assertFalse(value_morpheme_check.run(line_data, DUMMY_ANALYSIS_TARGET))

    def test_run_true_p(self) -> None:
        line_data = get_line_data(self.config, file_path="file_path", line='tizen', pattern=LINE_VALUE_PATTERN)
        self.assertTrue(ValueMorphemesCheck(None, 0).run(line_data, DUMMY_ANALYSIS_TARGET))

    def test_run_false_p(self) -> None:
        line_data = get_line_data(self.config, file_path="file_path", line='tizen', pattern=LINE_VALUE_PATTERN)
        self.assertFalse(ValueMorphemesCheck(None, 1).run(line_data, DUMMY_ANALYSIS_TARGET))


class TestValueMorphemesCheckFixture:

    @pytest.mark.parametrize(
        "line",
        [
            "the 0ne l1ne",
            "ani dammi lwnes",
            "burito",
            "31415926535897932384626433832795",  # first 32 symbols from https://oeis.org/A000796
            "27182818284590452353602874713526",  # first 32 symbols from https://oeis.org/A001113
        ])
    def test_value_couple_keyword_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueMorphemesCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        [
            "deadbeefdeadbeefdeadbeefdeadbeef",
            str(math.pi),
            str(math.e),
            "3141592653589793238462643383279",  # first 31 symbols from https://oeis.org/A000796
            "2718281828459045235360287471352",  # first 31 symbols from https://oeis.org/A001113
            "crack",
            "example",
            "motorcyclingend",
            "mulicrashprocid",
            "rgb195DiscretVideo",
            "GetSet",
            "GetDummyValue",
            "SetAnyString",
            "handleDeleteFriend",
            "acknowledgments",
            "somethingelse",
        ])
    def test_value_couple_keyword_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueMorphemesCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    @pytest.mark.parametrize("line", [AZ_STRING])
    def test_value_couple_keyword_check_arg_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueMorphemesCheck(threshold=9).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [AZ_STRING])
    def test_value_couple_keyword_check_arg_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueMorphemesCheck(threshold=8).run(line_data, DUMMY_ANALYSIS_TARGET) is True
