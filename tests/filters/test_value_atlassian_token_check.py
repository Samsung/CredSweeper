import base64
import binascii

import pytest

from credsweeper.common.constants import LATIN_1
from credsweeper.filters import ValueAtlassianTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueAtlassianTokenCheck:

    @pytest.mark.parametrize("line", ["12345:«VÏel\tSpÁß¡»q¾ä×^0÷ÕJür°eÆ\r"])
    def test_value_structured_token_check_p(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode(LATIN_1)).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=LINE_VALUE_PATTERN)
        assert ValueAtlassianTokenCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueAtlassianTokenCheck().run(bbdc_line_data, DUMMY_ANALYSIS_TARGET) is False
        payload = f"ATBB{encoded_line}"[:28]
        crc32 = f"{binascii.crc32(payload.encode('ascii')):08x}".upper()
        bbdc_line_data = get_line_data(file_path, line=f"{payload}{crc32}", pattern=LINE_VALUE_PATTERN)
        assert ValueAtlassianTokenCheck().run(bbdc_line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line",
                             ["12x45:asbdsa:28yd", "12345:bsskwjdsfskjdhrebewr", "022:OrganizationInvitation6080804"])
    def test_value_structured_token_check_n(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=LINE_VALUE_PATTERN)
        assert ValueAtlassianTokenCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueAtlassianTokenCheck().run(bbdc_line_data, DUMMY_ANALYSIS_TARGET) is True
        bbdc_line_data = get_line_data(file_path, line=f"ATBB{encoded_line[:28]}012345678", pattern=LINE_VALUE_PATTERN)
        assert ValueAtlassianTokenCheck().run(bbdc_line_data, DUMMY_ANALYSIS_TARGET) is True

