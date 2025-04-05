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
        (12,3.2448401902687922, 0.2001867347580528),
        (13,3.3305754195719484, 0.1987638281794566),
        (15,3.4840904247691813, 0.192504685389475),
        (16,3.544861791803441, 0.184688685917545),
        (17,3.613827056321014, 0.18707867741897827),
        (31,4.15268463818445, 0.1486133074700339),
        (32,4.177896164672521, 0.1472328639816872),
        (33,4.197883981615083, 0.14735097649694248),
        (sys.maxsize, 35.28, 0),
    ])
    def test_get_min_data_entropy_p(self, size: int, entropy: float, deviation: float) -> None:
        min_entropy = ValueEntropyBase32Check.get_min_data_entropy(size)
        diff = abs(min_entropy - (entropy - deviation))
        min_diff = deviation / 44
        max_diff = deviation / 4
        assert min_diff <= diff
        assert diff <= max_diff

    @pytest.mark.parametrize("size", [0, 1,  -1, -sys.maxsize])
    def test_get_min_data_entropy_n(self, size: int) -> None:
        assert 0 == ValueEntropyBase32Check.get_min_data_entropy(size) == 0
