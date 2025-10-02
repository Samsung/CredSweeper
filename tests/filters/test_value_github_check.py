import pytest

from credsweeper.filters import ValueGitHubCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueGitHubCheck:

    @pytest.mark.parametrize("line",
                             ["gh?_00000000000000000000000000000004WZ4EQ", "npm_00000000000000000000000000000004WZ4EQ"])
    def test_value_github_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueGitHubCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line",
                             ["hhh_00000000000000000000000000000004WZ4EQ", "npm_00000000000000000000000000000004WZAEQ"])
    def test_value_github_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueGitHubCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
