import pytest

from credsweeper.filters import ValueTokenBase36Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueTokenBase36Check:

    @pytest.mark.parametrize("line", ["wpv1jq9xwanbn3n"])
    def test_value_token_base36_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["100x200x300x400"])
    def test_value_token_base36_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True
