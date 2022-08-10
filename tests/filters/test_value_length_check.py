import pytest

from credsweeper.filters import ValueLengthCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueLengthCheck:

    @pytest.mark.parametrize("min_len", [4])
    def test_value_length_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture, min_len: int) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=r"(?P<value>.*$)")
        assert ValueLengthCheck(min_len).run(line_data) is False

    @pytest.mark.parametrize("line", ["Cra"])
    @pytest.mark.parametrize("min_len", [4])
    def test_value_length_check_n(self, file_path: pytest.fixture, line: str, min_len: int) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueLengthCheck(min_len).run(line_data) is True

    @pytest.mark.parametrize("min_len", [4])
    def test_value_length_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture,
                                             min_len: int) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueLengthCheck(min_len).run(line_data) is True
