import pytest

from credsweeper.filters import ValueCamelCaseCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueCamelCaseCheck:
    def test_value_camelcase_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=r"(?P<value>.*$)")
        assert ValueCamelCaseCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["CamelCase", "camelCase"])
    def test_value_camelcase_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueCamelCaseCheck().run(line_data) is True

    def test_value_camelcase_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueCamelCaseCheck().run(line_data) is True
