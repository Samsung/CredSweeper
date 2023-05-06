import base64

import pytest

from credsweeper.common import KeywordChecklist
from credsweeper.filters import ValueStructuredTokenCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueStructuredTokenCheck:

    @pytest.mark.parametrize("line", ["12345:asbdsa:28yd"])
    def test_value_couple_keyword_check_p(self, file_path: pytest.fixture, line: str) -> None:
        KeywordChecklist()
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=r"(?P<value>.*$)")
        assert ValueStructuredTokenCheck().run(line_data) is False
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=r"(?P<value>.*$)")
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is False

    @pytest.mark.parametrize("line", ["1234f:asbdsa:28yd"])
    def test_value_couple_keyword_check_n(self, file_path: pytest.fixture, line: str) -> None:
        KeywordChecklist()
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=r"(?P<value>.*$)")
        assert ValueStructuredTokenCheck().run(line_data) is True
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=r"(?P<value>.*$)")
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is True

    def test_value_couple_keyword_check_empty_value_n(self, file_path: pytest.fixture) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line="")
        assert ValueStructuredTokenCheck().run(line_data) is True
