import base64

import pytest

from credsweeper.filters import ValueJsonWebTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueJsonWebTokenCheck:

    @pytest.mark.parametrize("line", ["12345:asbdsa:28yd"])
    def test_value_jwt_check_p(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        jwt_like_line = base64.b64encode('{"typ":"JWT", "dummy": false}'.encode('ascii')).decode('ascii')
        jwt_line_data = get_line_data(file_path, line=f"{jwt_like_line}.{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueJsonWebTokenCheck().run(jwt_line_data, DUMMY_ANALYSIS_TARGET) is False
        # partially line
        jwt_line_data = get_line_data(file_path, line=f"{jwt_like_line}.AnyTailOfString", pattern=LINE_VALUE_PATTERN)
        assert ValueJsonWebTokenCheck().run(jwt_line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["1234f:asbdsa:28yd"])
    def test_value_jwt_check_n(self, file_path: pytest.fixture, line: str) -> None:
        encoded_line = base64.b64encode(line.encode('ascii')).decode('ascii')
        jwt_line_data = get_line_data(file_path, line=f"eyJungle.{encoded_line}", pattern=LINE_VALUE_PATTERN)
        assert ValueJsonWebTokenCheck().run(jwt_line_data, DUMMY_ANALYSIS_TARGET) is True
        jwt_line_data = get_line_data(file_path, line="eyJungle", pattern=LINE_VALUE_PATTERN)
        assert ValueJsonWebTokenCheck().run(jwt_line_data, DUMMY_ANALYSIS_TARGET) is True

