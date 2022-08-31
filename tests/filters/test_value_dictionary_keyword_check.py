import pytest

from credsweeper.common import KeywordChecklist
from credsweeper.filters import ValueDictionaryKeywordCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueDictionaryKeywordCheck:

    def test_value_dictionary_keyword_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line=success_line, pattern=r"(?P<value>.*$)")
        assert ValueDictionaryKeywordCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["typically", "password"])
    def test_value_dictionary_keyword_check_n(self, file_path: pytest.fixture, line: str) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueDictionaryKeywordCheck().run(line_data) is True

    @pytest.mark.parametrize("line", ["$e<Ret&kEy!", "23aWs#uh3"])
    def test_value_dictionary_keyword_check2_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueDictionaryKeywordCheck().run(line_data) is False

    def test_value_dictionary_keyword_check_none_value_n(self, file_path: pytest.fixture,
                                                         success_line: pytest.fixture) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line=success_line)
        assert ValueDictionaryKeywordCheck().run(line_data) is True
