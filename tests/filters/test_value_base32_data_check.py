import pytest

from credsweeper.filters import ValueBase32DataCheck
from tests.filters.conftest import LINE_VALUE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValueBase32DataCheck:

    @pytest.mark.parametrize("line", ["WXFES7QNTET5DQYC"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueBase32DataCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["PMRGSZBCHIYTEM35", "ABCDEFGHIJKLMNOP", "5555555555555555", "GAYDAMBQGAYDAMBQ"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueBase32DataCheck().run(line_data) is True

    def test_value_entropy_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueBase32DataCheck().run(line_data) is True
