import pytest

from credsweeper.filters import ValueBlocklistCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueBlocklistCheck:
    def test_value_blocklist_p(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=r"(?P<value>.*$)")
        assert ValueBlocklistCheck().run(line_data) is False

    @pytest.mark.parametrize("line", [
        "string12",
    ])
    def test_value_blocklist_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=r"(?P<value>.*$)")
        assert ValueBlocklistCheck().run(line_data) is True

    def test_value_blocklist_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueBlocklistCheck().run(line_data) is True
