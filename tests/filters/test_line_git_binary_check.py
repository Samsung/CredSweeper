import pytest

from credsweeper.filters import LineSpecificKeyCheck, LineGitBinaryCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestLineGitBinaryCheck:

    @pytest.mark.parametrize("line",
                             ['{"test":1,"pw":"sn2e8dgWwW","payload":"EYlS}b+C(YT)lWLGxNdj7Pw=w"}', 'XcmV?d00001'])
    def test_line_specific_key_check_p(self, file_path: pytest.fixture, line: str) -> None:
        cred_candidate = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert LineGitBinaryCheck().run(cred_candidate, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line",
                             ['zxNdj)EYlS}b8JGyg7Pw=wujtWvwg9)mv+;vvr}dADtX-(^(6N+C(YT)lWLG7tdu$7', 'HcmV?d00001'])
    def test_line_specific_key_check_n(self, file_path: pytest.fixture, line: str) -> None:
        cred_candidate = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert LineGitBinaryCheck().run(cred_candidate, DUMMY_ANALYSIS_TARGET) is True
