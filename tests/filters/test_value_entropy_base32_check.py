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
