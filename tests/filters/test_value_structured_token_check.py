import base64
import binascii

import pytest

from credsweeper.filters import ValueStructuredTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValueStructuredTokenCheck:

    @pytest.mark.parametrize("line", ["12345:asbdsa:28yd"])
    def test_value_structured_token_check_p(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(line_data) is False
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is False
        payload = f"ATBB{encoded_line}"
        crc32 = f"{binascii.crc32(payload.encode('ascii')):08x}".upper()
        bbdc_line_data = get_line_data(file_path, line=f"{payload}{crc32}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is False

    @pytest.mark.parametrize("line", ["12x45:asbdsa:28yd"])
    def test_value_structured_token_check_n(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(line_data) is True
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is True
        bbdc_line_data = get_line_data(file_path, line=f"ATBB{encoded_line}012345678", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is True

    def test_value_structured_token_check_empty_value_n(self, file_path: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line="")
        assert ValueStructuredTokenCheck().run(line_data) is True
