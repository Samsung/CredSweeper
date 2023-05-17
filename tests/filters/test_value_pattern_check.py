import pytest

from credsweeper.filters import ValuePatternCheck
from tests.filters.conftest import LINE_VALUE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestValuePatternCheck:

    def test_equal_pattern_check_n(self) -> None:
        cred_value = "Crackle123"
        expected = False
        actual = ValuePatternCheck().equal_pattern_check(cred_value)

        assert actual == expected

    def test_equal_pattern_check_p(self) -> None:
        cred_value = "AAAAAAA123"
        expected = True
        actual = ValuePatternCheck().equal_pattern_check(cred_value)

        assert actual == expected

    def test_ascending_pattern_check_n(self) -> None:
        cred_value = "Crackle123"
        expected = False
        actual = ValuePatternCheck().ascending_pattern_check(cred_value)

        assert actual == expected

    def test_ascending_pattern_check_p(self) -> None:
        cred_value = "Crackle1234"
        expected = True
        actual = ValuePatternCheck().ascending_pattern_check(cred_value)

        assert actual == expected

    def test_descending_pattern_check_n(self) -> None:
        cred_value = "Crackle321"
        expected = False
        actual = ValuePatternCheck().descending_pattern_check(cred_value)

        assert actual == expected

    def test_descending_pattern_check_p(self) -> None:
        cred_value = "Crackle4321"
        expected = True
        actual = ValuePatternCheck().descending_pattern_check(cred_value)

        assert actual == expected

    def test_value_similarity_check_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["Crackle4444", "Crackle1234", "Crackle4321"])
    def test_value_similarity_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck().run(line_data) is True

    def test_value_similarity_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValuePatternCheck().run(line_data) is True
