import pytest

from credsweeper.filters import ValueAllowlistCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET, SUCCESS_LINE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValueAllowlistCheck:

    @pytest.mark.parametrize(
        "line",
        [  #
            "password = $4eCr3t",  #
            "password = 'F(b7)]DAS^iCv0vqIJOvGg<5<F(lwQ'",  #
            "password = P@s$w0Rd",  #
            "password = ENCrackle123)",  #
            "password = ENC[Crackle123",  #
            "password = ${@35%1",  #
            "password = $?$Cr3t",  #
            "password = #{PA13",  #
            "password = #{{{{",  #
            "password = !t->(pass);",  #
            "password = ***test***",  #
            "password = .*@@@@@@",  #
            "pass=get->pass('''ARG",  #
        ])
    def test_value_allowlist_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=SUCCESS_LINE_PATTERN)
        assert ValueAllowlistCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        [  #
            "pass=get->pass(arg",  #
            "PASS:@@@hl@@@PASS@@@endhl@@@",  #
            "pass:='ENC(Crackle123)'",  #
            "pass:'ENC[Crackle123]'",  #
            "pass=${REMOVE_PREFIX#prefix}",  #
            "pass=$PASSWORD",  #
            "pass===#{PASSWORD}",  #
            "pass=>#{{PASSWORD}}",  #
            "pass:test*****",  #
            'PASS="${*}"',  #
            'PASS="$123"',  #
        ])
    def test_value_allowlist_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=SUCCESS_LINE_PATTERN)
        assert ValueAllowlistCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
