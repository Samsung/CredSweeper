import pytest

from credsweeper.filters import ValueFilePathCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueFilePathCheck:
    def test_value_file_path_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=r"(?P<value>.*$)")
        assert ValueFilePathCheck().run(line_data) is False

    @pytest.mark.parametrize("line", [
        "/Crackle/filepath", "C:\\\\Crackle\\filepath", "crackle/filepath", "crackle/file.path",
        "file:///Crackle/filepath/"
    ])
    def test_value_file_path_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueFilePathCheck().run(line_data) is True

    def test_value_file_path_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueFilePathCheck().run(line_data) is True
