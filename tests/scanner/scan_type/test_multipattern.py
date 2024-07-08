import unittest
from unittest.mock import MagicMock

from credsweeper.common.constants import MAX_LINE_LENGTH, CHUNK_STEP_SIZE
from credsweeper.config import Config
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import MultiPattern
from tests.filters.conftest import DUMMY_DESCRIPTOR


class TestMultiPattern(unittest.TestCase):

    def setUp(self) -> None:
        self.config = MagicMock(spec=Config)
        self.config.exclude_lines = []
        self.config.exclude_values = []
        self.config.use_filters = True
        self.rule = Rule(
            self.config, {
                "name": "MULTI_PATTERN_RULE",
                "severity": "info",
                "confidence": "moderate",
                "type": "multi",
                "values": ["(?P<value>a)", "(?P<value>b)"],
                "filter_type": [],
                "min_line_len": 0,
                "target": ["code"],
            })

    def test_oversize_line_n(self) -> None:
        long_line_a: str = 'x' * CHUNK_STEP_SIZE + ' a ' + 'x' * CHUNK_STEP_SIZE
        long_line_b: str = 'x' * CHUNK_STEP_SIZE + ' b ' + 'x' * CHUNK_STEP_SIZE
        self.assertEqual(2 * CHUNK_STEP_SIZE + 3, len(long_line_a))
        target = AnalysisTarget(0, [long_line_a, long_line_b], [1, 2], DUMMY_DESCRIPTOR)
        result = MultiPattern.run(self.config, self.rule, target)
        self.assertEqual(1, len(result))

    def test_oversize_line_p(self) -> None:
        long_line: str = 'x' * MAX_LINE_LENGTH
        self.assertEqual(MAX_LINE_LENGTH, len(long_line))
        target = AnalysisTarget(0, [long_line + ' a', long_line + ' b'], [1, 2], DUMMY_DESCRIPTOR)
        result = MultiPattern.run(self.config, self.rule, target)
        self.assertEqual(1, len(result))
