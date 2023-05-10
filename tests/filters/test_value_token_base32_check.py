import pytest

from credsweeper.common import KeywordChecklist
from credsweeper.filters import ValueCoupleKeywordCheck, ValueTokenBase32Check
from tests.test_utils.dummy_line_data import get_line_data


class TestValueTokenBase32Check:

    @pytest.mark.parametrize("line", ["NJ3DBYHEKQJD5PZS"])
    def test_value_token_base32_check_p(self, file_path: pytest.fixture, line: str) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueTokenBase32Check().run(line_data) is False

    @pytest.mark.parametrize("line", ["OOOOOOMMMMMMMMMM"])
    def test_value_token_base32_check_n(self, file_path: pytest.fixture, line: str) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueTokenBase32Check().run(line_data) is True

    def test_value_token_base32_check_empty_value_n(self, file_path: pytest.fixture) -> None:
        KeywordChecklist()
        line_data = get_line_data(file_path, line="")
        assert ValueTokenBase32Check().run(line_data) is True
