import pytest

from credsweeper.filters import ValueEntropyCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueEntropyCheck:

    @pytest.mark.parametrize(
        "line",
        [
            "YDVYJPWTZRRO5"
            "0123456789abcdef",  #
            "18eea36e-e870-f279-4021-12f45ee03e37",  #
            "VP6V3TM9J7TGP9CUVWXY6GJ7K",  #
            "VP6V3-TM9J7-TGP9C-UVWXY-6GJ7K",  #
        ])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyCheck(threshold=64).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        [
            "YDVYJPWTZRRO",  #
            "0123456789abcde",  #
            "000000000000000",  #
            "aP6b3TM9x7",  #
            "XFL-T18853",  #
        ])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyCheck(threshold=64).run(line_data, DUMMY_ANALYSIS_TARGET) is True
