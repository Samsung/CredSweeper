import pytest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import SeparatorUnusualCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestSeparatorUnusualCheck:

    @pytest.mark.parametrize("line", [
        "password = crackle!",
    ])
    def test_separator_unusual_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path,
                                  line=line,
                                  pattern="(?P<keyword>password)[^:='\"`<>]*\\s*(?P<separator>=)\\s*(?P<value>.*$)")
        assert SeparatorUnusualCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [
        "password crackle!",
        "password ++ crackle!",
        "password >> crackle!",
        "password == crackle!",
        "password != crackle!",
    ])
    def test_separator_unusual_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path,
                                  line=line,
                                  pattern="(?P<keyword>password)[^:='\"`<>]*\\s*(?P<separator>=)\\s*(?P<value>.*$)")
        assert SeparatorUnusualCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
