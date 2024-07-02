import pytest

from credsweeper.filters import ValueEntropyBase64Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueEntropyBase64Check:

    @pytest.mark.parametrize("line", ["0wz92+C275sfJHb2r5tS5o/u9y862lR4"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase64Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["D6018D91B502C475E8FC27D5F05387558A002B9283DA7E252896950917476ECE"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase64Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True
