import pytest

from credsweeper.filters import ValueHexNumberCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueHexNumberCheck:

    @pytest.mark.parametrize("line", ["0xabcdI234", "0xabcd0987654321371"])
    def test_value_number_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueHexNumberCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["0xaBcd1234", "0xAbCd098765432137"])
    def test_value_number_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueHexNumberCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
