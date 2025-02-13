import pytest

from credsweeper.filters import ValueTokenBase32Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueTokenBase32Check:

    @pytest.mark.parametrize("line", ["4K26IPW7VBHMFT4D", "NAQ4BVWT", "WXFES7QNTET5DQYC"])
    def test_value_token_base32_check_p(self, line: str) -> None:
        # import string;import random;print(''.join(random.choices(string.ascii_uppercase+'234567', k=16)))
        line_data = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase32Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["OOOOOOMMMMMMMMMM", "1MZ0A9L2", "QAZXSWEDCVFRTGBN"])
    def test_value_token_base32_check_n(self, line: str) -> None:
        line_data = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase32Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True
