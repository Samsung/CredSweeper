import pytest

from credsweeper.filters import ValueEntropyCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueEntropyCheck:

    @pytest.mark.parametrize("line", ["2jmj7l5rSw0yVb"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueEntropyCheck().run(line_data) is False

    @pytest.mark.parametrize("line", ["examplekey"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueEntropyCheck().run(line_data) is True

    def test_value_entropy_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueEntropyCheck().run(line_data) is True
