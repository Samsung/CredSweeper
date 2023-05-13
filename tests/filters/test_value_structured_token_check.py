import base64

import pytest
from credsweeper.filters import ValueStructuredTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValueStructuredTokenCheck:

    @pytest.mark.parametrize("line", ["12345:asbdsa:28yd"])
    def test_value_couple_keyword_check_p(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(line_data) is False
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is False
        jwt_like_line = base64.b64encode('{"tip":"JWT", "dummy": false}'.encode('ascii')).decode('ascii')
        jwt_line_data = get_line_data(file_path, line=f"{jwt_like_line}.{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(jwt_line_data) is False
        # partially line
        jwt_line_data = get_line_data(file_path, line=f"{jwt_like_line[:-3]}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(jwt_line_data) is False

    @pytest.mark.parametrize("line", ["1234f:asbdsa:28yd"])
    def test_value_couple_keyword_check_n(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=encoded_line, pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(line_data) is True
        bbdc_line_data = get_line_data(file_path, line=f"BBDC-{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(bbdc_line_data) is True
        jwt_line_data = get_line_data(file_path, line=f"eyJungle.{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(jwt_line_data) is True
        jwt_line_data = get_line_data(file_path, line="eyJungle", pattern=LINE_VALUE_PATTERN)
        assert ValueStructuredTokenCheck().run(jwt_line_data) is True

    def test_value_couple_keyword_check_empty_value_n(self, file_path: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line="")
        assert ValueStructuredTokenCheck().run(line_data) is True
