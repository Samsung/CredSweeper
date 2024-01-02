import pytest

from credsweeper.filters import ValueTokenBase32Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueTokenBase32Check:

    @pytest.mark.parametrize("line", ["WXFES7QNTET5DQYC"])
    def test_value_token_base32_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase32Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["OOOOOOMMMMMMMMMM"])
    def test_value_token_base32_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase32Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_value_token_base32_check_empty_value_n(self, file_path: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line="")
        assert ValueTokenBase32Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True
