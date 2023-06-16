import pytest

from credsweeper.common.constants import Chars
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValueNotPartEncodedCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueNotPartEncodedCheck:

    def test_value_not_part_encoded_p(self, config: pytest.fixture) -> None:
        target = AnalysisTarget("XXX", 1, ["AAA", "BBB"])
        line_data = LineData(config, "XXX", 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is False

    def test_value_not_part_encoded_n(self, config: pytest.fixture) -> None:
        target = AnalysisTarget("XXX", 2, [Chars.BASE64STD_CHARS.value, "XXX"])
        line_data = LineData(config, "XXX", 2, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        target = AnalysisTarget("XXX", 1, ["XXX", Chars.BASE64STD_CHARS.value])
        line_data = LineData(config, "XXX", 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        target = AnalysisTarget("XXX", 333, [Chars.BASE64STD_CHARS.value, "XXX"])
        line_data = LineData(config, "XXX", 333, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True

    def test_value_not_part_encoded_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueNotPartEncodedCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
