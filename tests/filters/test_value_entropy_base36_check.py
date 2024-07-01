import pytest

from credsweeper.filters import ValueEntropyBase36Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueEntropyBase36Check:

    @pytest.mark.parametrize("line", ["wpv1jq9xwanbn3n", "snck3id95hab1jfnvlp109fs8"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["testtesttest", "noncenoncenoncenoncenonce"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True
