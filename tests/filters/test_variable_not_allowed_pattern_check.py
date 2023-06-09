import pytest

from credsweeper.filters import VariableNotAllowedPatternCheck
from tests.filters.conftest import LINE_VARIABLE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestVariableNotAllowedPatternCheck:

    def test_variable_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=LINE_VARIABLE_PATTERN)
        assert VariableNotAllowedPatternCheck().run(line_data) is False

    @pytest.mark.parametrize("line", [
        "<crackle>", "{{crackle}}", "@GIREOGI", "! ", "> ", "< ", "+ ", "* ", "/ ", "^ ", "|", "sharing_public_key",
        "my_pubkey"
    ])
    def test_variable_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VARIABLE_PATTERN)
        assert VariableNotAllowedPatternCheck().run(line_data) is True

    def test_variable_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert VariableNotAllowedPatternCheck().run(line_data) is True
