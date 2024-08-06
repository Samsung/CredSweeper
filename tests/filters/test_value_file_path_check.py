import pytest

from credsweeper.filters import ValueFilePathCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueFilePathCheck:

    @pytest.mark.parametrize("line", [
        "5//0KCPafDhZvtCyiKFeDGT0ZGHiIE0ClIWrLC7tZ1WE5vHc4Y2qi1IhPy3Pz5fmCe9OPIxEZNUg7SJF9nwQj2lIdXU0",
    ])
    def test_value_file_path_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueFilePathCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        [
            "crackle/filepath.txt",
            "/home/user/tmp",  # simple path
            "../..",  # path
            "dir/..",  # path
            "../dir",  # path
            "file:///Crackle/filepath/",  # path from browser url
            "~/.custompass",  # path with synonym
            "./sshpass.sh",  # path with synonym
            "crackle/file.path",  #
            "C:\\Crackle\\filepath",  #
        ])
    def test_value_file_path_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueFilePathCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
