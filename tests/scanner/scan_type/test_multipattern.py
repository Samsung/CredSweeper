import unittest
from unittest.mock import MagicMock

from credsweeper.common.constants import MAX_LINE_LENGTH, CHUNK_STEP_SIZE
from credsweeper.config.config import Config
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules.rule import Rule
from credsweeper.scanner.scan_type.multi_pattern import MultiPattern
from tests import AZ_STRING
from tests.filters.conftest import DUMMY_DESCRIPTOR


class TestMultiPattern(unittest.TestCase):

    def setUp(self) -> None:
        self.maxDiff = None
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

    def test_get_line_positions_n(self):
        target = AnalysisTarget(0, [AZ_STRING], [1], DUMMY_DESCRIPTOR)
        self.assertListEqual([0], MultiPattern.get_line_positions(0, target))
        target = AnalysisTarget(-1, [AZ_STRING], [1], DUMMY_DESCRIPTOR)
        self.assertListEqual([], MultiPattern.get_line_positions(-1, target))

    def test_get_line_positions_p(self):
        lines = [str(1 + x) for x in range(42)]
        line_nums = [1 + x for x in range(42)]
        target = AnalysisTarget(0, lines, line_nums, DUMMY_DESCRIPTOR)
        self.assertListEqual(list(range(11)), MultiPattern.get_line_positions(0, target))
        self.assertListEqual([41 - x for x in range(11)], MultiPattern.get_line_positions(41, target))
        self.assertListEqual([21, 22, 20, 23, 19, 24, 18, 25, 17, 26, 16, 27, 15, 28, 14, 29, 13, 30, 12, 31, 11],
                             MultiPattern.get_line_positions(21, target))
        lines[20] = '{'
        target = AnalysisTarget(0, lines, line_nums, DUMMY_DESCRIPTOR)
        self.assertListEqual([21, 22, 23, 20, 24, 19, 25, 18, 26, 17, 27, 16, 28, 15, 29, 14, 30, 13, 31, 12, 11],
                             MultiPattern.get_line_positions(21, target))
        lines[22] = '}'
        target = AnalysisTarget(0, lines, line_nums, DUMMY_DESCRIPTOR)
        self.assertListEqual([21, 22, 20, 23, 19, 24, 18, 25, 17, 26, 16, 27, 15, 28, 14, 29, 13, 30, 12, 31, 11],
                             MultiPattern.get_line_positions(21, target))
        lines[16] = '{' * 10000
        target = AnalysisTarget(0, lines, line_nums, DUMMY_DESCRIPTOR)
        self.assertListEqual([21, 22, 20, 23, 19, 24, 18, 25, 17, 26, 27, 28, 29, 30, 31, 16, 15, 14, 13, 12, 11],
                             MultiPattern.get_line_positions(21, target))
