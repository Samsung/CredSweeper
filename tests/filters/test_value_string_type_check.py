import pytest

from credsweeper.config import Config
from credsweeper.filters import ValueStringTypeCheck
from credsweeper.utils import Util
from tests.test_utils.dummy_line_data import get_line_data


class TestValueStringTypeCheck:
    success_lines = ['test = "test_key"', "#test = test_key"]
    fail_line = ["test = test_key"]

    @pytest.mark.parametrize("line", success_lines)
    def test_value_string_type_check_p(self, line: str, config: Config) -> None:
        file_path = "path.py"
        pattern = Util.get_keyword_pattern("test")
        line_data = get_line_data(config, file_path, line=line, pattern=pattern)
        assert ValueStringTypeCheck(config).run(line_data) is False

    @pytest.mark.parametrize("line", fail_line)
    def test_value_string_type_check_n(self, line: str, config: Config) -> None:
        file_path = "path.py"
        pattern = Util.get_keyword_pattern("test")
        line_data = get_line_data(config, file_path, line=line, pattern=pattern)
        assert ValueStringTypeCheck(config).run(line_data) is True

    @pytest.mark.parametrize("line", success_lines)
    def test_value_string_type_check_none_path_n(self, line: str, config: Config) -> None:
        file_path = None
        pattern = Util.get_keyword_pattern("test")
        line_data = get_line_data(config, file_path, line=line, pattern=pattern)
        assert ValueStringTypeCheck(config).run(line_data) is True

    @pytest.mark.parametrize("line", fail_line)
    def test_value_string_type_check_not_quoted_source_file_p(self, line: str, config: Config) -> None:
        file_path = "path.yaml"
        pattern = Util.get_keyword_pattern("test")
        line_data = get_line_data(
            config,
            file_path,
            line=line,
            pattern=pattern,
        )
        assert ValueStringTypeCheck(config).run(line_data) is False

    @pytest.mark.parametrize("line", success_lines)
    def test_value_string_type_check_none_value_n(self, line: str, config: Config) -> None:
        file_path = "path.py"
        line_data = get_line_data(config, file_path, line=line)
        assert ValueStringTypeCheck(config).run(line_data) is True
