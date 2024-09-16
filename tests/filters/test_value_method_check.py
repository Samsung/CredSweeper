import pytest

from credsweeper.filters import ValueMethodCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET, SUCCESS_LINE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValueMethodCheck:

    def test_value_method_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=SUCCESS_LINE_PATTERN)
        assert ValueMethodCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["pass=Crac.method()", "pass=Crac_function"])
    def test_value_method_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=SUCCESS_LINE_PATTERN)
        assert ValueMethodCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
