import pytest

from credsweeper.config import Config
from credsweeper.filters import ValueMaskedCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueMaskedCheckFixture:

    @pytest.mark.parametrize("line", ["**1***", "12*****"])
    def test_value_masked_check_p(self, file_path: pytest.fixture, config: Config, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueMaskedCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["*****", "1*****", "1*****2*****"])
    def test_value_masked_check_n(self, file_path: pytest.fixture, config: Config, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueMaskedCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_value_masked_check_none_value_n(self, file_path: pytest.fixture, config: Config,
                                             success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueMaskedCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is True
