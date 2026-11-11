import pytest

from credsweeper.filters import ValueFilePathCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueFilePathCheck:

    @pytest.mark.parametrize(
        "line",
        [
            "FILE:\\\\Program Files(x86)\\\\Games",  #
            "/u5r/d3v/f1le",  #
            "5//0KCPafDhZvtCwqrsyiKFeDGT_0ZGHiI-E0ClIWrLC7tZ1WE5vHc4-Y2qi1IhPy3Pz5fmCe9OPIxEZUONUg7SWJF9nwQ_j2lIdXU0",  #
            "SDF;4s]dDe",  #
        ])
    def test_value_file_path_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueFilePathCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        [
            "OTHER_ETC/job/OTHER_CPI6_COVERAGE/376/GCOV_32Coverage_32Report_12",
            "X:\\234mb6\\324bb-233nb5-v65",  #
            "~/.wine/proc/drive/@C:\\\\Program Files(x86)\\\\Games",  #
            "[DEPOT]/${path}/$(date)/config/credentials",  #
            "/mnt/x",  #
            "/srv/x",  #
            "/var/lib/",  # path
            "~/.ssh/id_rsa",  # path
            "../key",  # path
            "../../log",  # path
            "/home/user/.ssh/id_rsa",  # path
            "../.ssh/id_rsa",  # path
            "crackle/filepath.txt",
            "/home/user/tmp",  # simple path
            "file:///Crackle/filepath/",  # path from browser url
            "~/.custompass",  # path with synonym
            "./sshpass.sh",  # path with synonym
            "crackle/file.path",  #
            "C:\\Crackle\\filepath",  #
        ])
    def test_value_file_path_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueFilePathCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
