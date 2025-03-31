import pytest

from credsweeper.filters import ValueBase32DataCheck, ValuePrimeFlowerCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValuePrimeFlowerCheck:

    @pytest.mark.parametrize("line", ["417072696c0931737409416c657274217e254307"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValuePrimeFlowerCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["417072696c0d3273740d416c65727421a7c5c9b7"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValuePrimeFlowerCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
