import sys

import pytest

from credsweeper.filters import ValueEntropyBase32Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueEntropyBase32Check:

    @pytest.mark.parametrize("line", ["WXFES7QNTET5DQYC"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase32Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["200X300X4000X123"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase32Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    @pytest.mark.parametrize(("size", "entropy", "deviation"), [
        (16, 3.553197207016156, 0.20104579535116426),
        (32, 4.175560617601108, 0.15800526502749024),
        (33, 4.1969606087810565, 0.15484387204591749),
        (sys.maxsize, 4.04, 0),
    ])
    def test_get_min_data_entropy_p(self, size: int, entropy: float, deviation: float) -> None:
        min_entropy = ValueEntropyBase32Check.get_min_data_entropy(size)
        diff = abs(min_entropy - (entropy - deviation))
        max_diff = deviation / 4
        assert 0 <= diff
        assert diff <= max_diff

    @pytest.mark.parametrize("size", [0, 1, -1, -sys.maxsize])
    def test_get_min_data_entropy_n(self, size: int) -> None:
        assert 0 == ValueEntropyBase32Check.get_min_data_entropy(size) == 0
