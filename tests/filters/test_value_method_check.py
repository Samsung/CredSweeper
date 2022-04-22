import pytest

from credsweeper.filters import ValueMethodCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueMethodCheck:

    def test_value_method_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=r"(?P<value>.*$)")
        assert ValueMethodCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["Crac.method()", "Crac_function"])
    def test_value_method_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueMethodCheck().run(line_data) is True

    def test_value_method_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueMethodCheck().run(line_data) is True
