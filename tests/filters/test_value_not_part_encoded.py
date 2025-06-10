import pytest

from credsweeper.common.constants import Chars
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValueNotPartEncodedCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_DESCRIPTOR


class TestValueNotPartEncodedCheck:

    def test_value_not_part_encoded_p(self, config: pytest.fixture) -> None:
        val = 'Q' * 64
        target = AnalysisTarget(0, [val, '/usr/local/host/'], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, val, 0, 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is False
        target = AnalysisTarget(0, ["AAA", "BBB"], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, "XXX", 0, 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is False

    def test_value_not_part_encoded_n(self, config: pytest.fixture) -> None:
        val = 'Q' * 64
        target = AnalysisTarget(0, [val, '/etc/localhost=='], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, val, 0, 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        val = 'Q' * 64
        target = AnalysisTarget(0, [val, '0123456789ABCDEF'], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, val, 0, 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        val = "/123" + 'Q' * 64
        target = AnalysisTarget(0, [val, '/123456789ABCDE='], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, val, 0, 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        target = AnalysisTarget(1, ['Q' * 64, val, "1234"], [1, 2, 3], DUMMY_DESCRIPTOR)
        line_data = LineData(config, val, 1, 2, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        target = AnalysisTarget(1, [Chars.BASE64STD_CHARS.value, "XXX"], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, "XXX", 1, 2, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        target = AnalysisTarget(0, ["XXX", Chars.BASE64STD_CHARS.value], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, "XXX", 0, 1, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
        target = AnalysisTarget(1, [Chars.BASE64STD_CHARS.value, "XXX"], [1, 2], DUMMY_DESCRIPTOR)
        line_data = LineData(config, "XXX", 1, 333, "", "", "", LINE_VALUE_PATTERN)
        assert ValueNotPartEncodedCheck().run(line_data, target) is True
