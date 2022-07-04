import pytest

from credsweeper.filters import ValueAsciiCheck
from tests.test_utils.dummy_line_data import get_line_data


class TestValueAsciiCheck:

    @pytest.mark.parametrize("value", [
        '"AKIAGIREOGIAWSKEY123,',
        '"AKIAGIREOGIAWSKEY123,u00ac|\u009a\u00d7l\u00ce\u001a\u0005\u00f2',
    ])
    def test_value_ascii_check_p(self, file_path: pytest.fixture, value: str) -> None:
        cred_candidate = get_line_data(file_path, line="", pattern=r"(?P<value>.*$)")
        cred_candidate.value = value
        assert ValueAsciiCheck().run(cred_candidate) is False

    @pytest.mark.parametrize("value", [
        '\u00f1',
    ])
    def test_value_ascii_check_n(self, file_path: pytest.fixture, value: str) -> None:
        cred_candidate = get_line_data(file_path, line="", pattern=r"(?P<value>.*$)")
        cred_candidate.value = value
        assert ValueAsciiCheck().run(cred_candidate) is True
