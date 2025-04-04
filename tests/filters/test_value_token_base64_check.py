import pytest

from credsweeper.filters import ValueTokenBase64Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueTokenBase64Check:

    @pytest.mark.parametrize(
        "line",
        [
            "oXIO7p2R4Sx5UcHmUacu0-ojM8ELvCeskmyPuu4yaexoh5ExL4AFOWWI08G-IBVZ",  # 64
            "9BlYTo-Fcthl_75PKfKQIWlYA6alA2uy",  # 32
            "23OY2aMY4U3ubsQwBPvdyfYr",  # 24
            "wSpv1jq9xwaXbn3n",  # 16
        ])
    def test_value_token_base64_check_p(self, line: str) -> None:
        # import string;import random;print(''.join(random.choices(string.digits+string.ascii_letters+'-_', k=64)))
        line_data = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase64Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        [
            "0oKiLoKkjUIhbYygVfcrTt6Dree3dSsBnJjiJKklLpMbV71X1QaSwDe23-9O_o01",  # 64
            "09uulkjhbmnbvft565d4ddxvcvswq232",  # 32
            "21WEasdVCfGGyrY6Ui8LkLpO",  # 24
            "100x200x3S00x400",  # 16
        ])
    def test_value_token_base64_check_n(self, line: str) -> None:
        line_data = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueTokenBase64Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True
