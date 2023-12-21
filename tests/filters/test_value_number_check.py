import pytest

from credsweeper.filters import ValueNumberCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueNumberCheck:

    @pytest.mark.parametrize("line", ["0123423423x", "abcdefg", "0123456789abcdef012345"])
    def test_value_number_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueNumberCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [
        "0123456789abcdef01234", "0123456789abcdef0123U", "0x0123456789abcdefULL", "555", "314ULL", "0xabcdefU", "0xfL",
        "010101010101", "-201760", "-1ULL"
    ])
    def test_value_number_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueNumberCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_value_number_check_none_value_n(self, file_path: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line="")
        assert ValueNumberCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
