import pytest

from credsweeper.filters import ValueTokenCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET, KEYWORD_PASSWORD_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValueTokenCheck:

    def test_value_token_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=KEYWORD_PASSWORD_PATTERN)
        assert ValueTokenCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["pass=Crac>crackle1", "pass=my<password", "pass=my)password"])
    def test_value_token_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=KEYWORD_PASSWORD_PATTERN)
        assert ValueTokenCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
