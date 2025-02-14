import pytest

from credsweeper.filters import ValueTokenBase36Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueTokenBase36Check:

    @pytest.mark.parametrize(
        "line",
        [
            "jvzec4y51fkrrd39czz1nfbw",  # 24
            "nf6lqy74gp53f7w08gn4l0vrk",  # 25
            "wpv1jq9xwanbn3n",  # 15
            "123456789",  # 9 - not calculated
        ])
    def test_value_token_base36_check_p(self, line: str) -> None:
        # import string;import random;print(''.join(random.choices(string.digits+string.ascii_lowercase, k=15)))
        line_data = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        [
            "100x200x300x400",  # 15
            "qwertyui",  # 8
            "0o9i8u7y6t5r4e3",  # 15
            "0k9j8h7g6f5d4s3a",  # 16
            "gfkjjhgy7r457y54jfhhgvcnf",  # 25
        ])
    def test_value_token_base36_check_n(self, line: str) -> None:
        line_data = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase36Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True
