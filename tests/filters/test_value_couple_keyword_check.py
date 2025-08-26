import pytest

from credsweeper.filters import ValueCoupleKeywordCheck
from tests import AZ_STRING
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueCoupleKeywordCheck:

    @pytest.mark.parametrize("line", ["the 0ne l1ne", "ani dammi lwnes", "burito"])
    def test_value_couple_keyword_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueCoupleKeywordCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [
        "crack",
        "example",
        "motorcyclingend",
        "mulicrashprocid",
        "rgb195DiscretVideo",
        "GetSet",
        "GetDummyValue",
        "SetAnyString",
        "handleDeleteFriend",
        "acknowledgments",
    ])
    def test_value_couple_keyword_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueCoupleKeywordCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    @pytest.mark.parametrize("line", [AZ_STRING])
    def test_value_couple_keyword_check_arg_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueCoupleKeywordCheck(threshold=9).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [AZ_STRING])
    def test_value_couple_keyword_check_arg_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueCoupleKeywordCheck(threshold=8).run(line_data, DUMMY_ANALYSIS_TARGET) is True
