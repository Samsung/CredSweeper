import pytest

from credsweeper.filters import ValuePlaceholderCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET, LINE_VALUE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValuePlaceholderCheck:

    @pytest.mark.parametrize("value", [
        "changeme", "your_password", "dummy_api_key", "example_key", "placeholder", "test123", "xxxxx",
    ])
    def test_placeholder_value_n(self, value: str) -> None:
        line_data = get_line_data(line=value, pattern=LINE_VALUE_PATTERN)
        assert ValuePlaceholderCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_example_path_n(self) -> None:
        line_data = get_line_data(file_path="tests/fixtures/config.py", line="real-looking-value",
                                  pattern=LINE_VALUE_PATTERN)
        assert ValuePlaceholderCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_real_value_p(self) -> None:
        line_data = get_line_data(file_path="src/config.py", line="a91f0c7e2b4d8a6f13c5e7b902d4f68a",
                                  pattern=LINE_VALUE_PATTERN)
        assert ValuePlaceholderCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False