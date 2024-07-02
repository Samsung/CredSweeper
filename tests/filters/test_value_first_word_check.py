import pytest

from credsweeper.filters import ValueFirstWordCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueFirstWordCheck:

    def test_value_first_word_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=LINE_VALUE_PATTERN)
        assert ValueFirstWordCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["{tokens"])
    def test_value_first_word_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueFirstWordCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
