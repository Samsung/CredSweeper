import sys

import pytest

from credsweeper.filters import ValueEntropyBase36Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueEntropyBase36Check:

    @pytest.mark.parametrize("line", ["2wp3v1jq9x1wa87n0bn5n46e", "snck3id95hab1jfnvlp109fs8"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["testtesttest", "noncenoncenoncenoncenonce"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    @pytest.mark.parametrize(("size", "entropy", "deviation"), [
        (15, 3.374, 0.0),
        (16, 3.593320328115991, 0.19663735985864308),
        (24, 4.0019667180259315, 0.1767051932594335),
        (25, 4.039642026714182, 0.1731145889575481),
        (sys.maxsize, 3.9, 0),
    ])
    def test_get_min_data_entropy_p(self, size: int, entropy: float, deviation: float) -> None:
        min_entropy = ValueEntropyBase36Check.get_min_data_entropy(size)
        diff = abs(min_entropy - (entropy - deviation))
        max_diff = deviation / 4
        assert 0 <= diff
        assert diff <= max_diff

    @pytest.mark.parametrize("size", [0, 1, -1, -sys.maxsize])
    def test_get_min_data_entropy_n(self, size: int) -> None:
        assert 0 == ValueEntropyBase36Check.get_min_data_entropy(size) == 0
