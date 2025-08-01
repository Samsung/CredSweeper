import pytest

from credsweeper.filters import ValueBase32DataCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueBase32DataCheck:

    @pytest.mark.parametrize("line", ["SUAML2GCZ7IK7E7UD4VZ7ELPZW7DK2ZNL35WSMW3IORHC3BWBSDQXUQRBU", "WXFES7QNTET5DQYC"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueBase32DataCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["PMRGSZBCHIYTEM35", "ABCDEFGHIJKLMNOP", "5555555555555555", "GAYDAMBQGAYDAMBQ"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueBase32DataCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
