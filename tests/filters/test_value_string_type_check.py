import pytest

from credsweeper.config import Config
from credsweeper.filters import ValueStringTypeCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET, SUCCESS_LINE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValueStringTypeCheck:

    def test_value_string_type_check_p(self, config: Config, success_line: pytest.fixture) -> None:
        file_path = "path.txt"
        line_data = get_line_data(config, file_path, line=success_line, pattern=SUCCESS_LINE_PATTERN)
        assert ValueStringTypeCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["pass = Pa55vArIabLe"])
    def test_value_string_type_check_n(self, config: Config, line: str) -> None:
        file_path = "path.py"
        line_data = get_line_data(config, file_path, line=line, pattern=SUCCESS_LINE_PATTERN)
        assert ValueStringTypeCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_value_string_type_check_none_path_n(self, config: Config, success_line: pytest.fixture) -> None:
        # even file_path is None it means "" - no extension
        file_path = None
        line_data = get_line_data(config, file_path, line=success_line, pattern=SUCCESS_LINE_PATTERN)
        assert ValueStringTypeCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["pass = test_key"])
    def test_value_string_type_check_not_quoted_source_file_n(self, line: str, config: Config) -> None:
        file_path = "path.yaml"
        line_data = get_line_data(
            config,
            file_path,
            line=line,
            pattern=SUCCESS_LINE_PATTERN,
        )
        assert ValueStringTypeCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is False
