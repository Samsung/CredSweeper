import pytest

from credsweeper.common import KeywordChecklist
from credsweeper.filters import ValueCoupleKeywordCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueCoupleKeywordCheck:

    @pytest.mark.parametrize("line", ["the 0ne l1ne", "ani dammi lwnes", "burito"])
    def test_value_couple_keyword_check_p(self, file_path: pytest.fixture, line: str) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueCoupleKeywordCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["GetSet", "GetDummyValue", "SetAnyString"])
    def test_value_couple_keyword_check_n(self, file_path: pytest.fixture, line: str) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueCoupleKeywordCheck().run(line_data) is True

    def test_value_couple_keyword_check_none_value_n(self, file_path: pytest.fixture) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line="")
        assert ValueCoupleKeywordCheck().run(line_data) is True
