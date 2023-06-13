import pytest

from credsweeper.filters import ValueBase64DataCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueBase64DataCheck:

    @pytest.mark.parametrize("line", ["0DiwN2M1NTeGd6S6jU","o9LN618aEaH32KhF7e_L"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueBase64DataCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["eyJ0eXAiOiJKV1QiLC", "2AA219GG746F88F6DDA0D852A0FD3211"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueBase64DataCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_value_entropy_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueBase64DataCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
