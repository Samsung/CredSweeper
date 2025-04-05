import sys

import pytest

from credsweeper.filters import ValueEntropyBase64Check
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueEntropyBase64Check:

    @pytest.mark.parametrize("line", ["0wz92+C275sfJHb2r5tS5o/u9y862lR4"])
    def test_value_entropy_check_p(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase64Check().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["D6018D91B502C475E8FC27D5F05387558A002B9283DA7E252896950917476ECE"])
    def test_value_entropy_check_n(self, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueEntropyBase64Check().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    @pytest.mark.parametrize(("size", "entropy", "deviation"), [
        (12, 3.402832674668131, 0.16390772966021167),
        (18, 3.901894088228036, 0.1507035617252249),
        (20, 4.027133655487158, 0.14789802297157817),
        (25, 4.2799509786429715, 0.1469939952270194),
        (35, 4.636189424519627, 0.1325272934890342),
        (45, 4.877311178212475, 0.11797362443045391),
        (65, 5.183120734812424, 0.10823342697093974),
        (80, 5.329761693425697, 0.09159231726044716),
        (100, 5.4658131564512376, 0.08210420023521858),
        (256, 5.77, 0),
        (512, 5.89, 0),
        (1024, 5.94, 0),
        (sys.maxsize, 5.94, 0),
    ])
    def test_get_min_data_entropy_p(self, size: int, entropy: float, deviation: float) -> None:
        min_entropy = ValueEntropyBase64Check.get_min_data_entropy(size)
        diff = abs(min_entropy - (entropy - deviation))
        max_diff = deviation / 4
        assert 0 <= diff
        assert diff <= max_diff

    @pytest.mark.parametrize("size", [0, 1, -1, -sys.maxsize])
    def test_get_min_data_entropy_n(self, size: int) -> None:
        assert 0 == ValueEntropyBase64Check.get_min_data_entropy(size) == 0
