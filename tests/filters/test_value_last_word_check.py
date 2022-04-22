import pytest

from credsweeper.filters import ValueLastWordCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueLastWordCheck:

    def test_value_last_word_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=r"(?P<value>.*$)")
        assert ValueLastWordCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["tokens = value:"])
    def test_value_last_word_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueLastWordCheck().run(line_data) is True

    def test_value_last_word_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueLastWordCheck().run(line_data) is True
