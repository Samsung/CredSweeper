import random
import string
import unittest
from unittest.mock import MagicMock

from credsweeper.common.constants import MAX_LINE_LENGTH
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
                "type": "multi",
                "values": ["a", "b"],
                "filter_type": [],
                "min_line_len": 0,
                "doc_available": False,
            })

    def test_oversize_line_n(self) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        long_line += 'OVERSIZE'
        self.assertLess(MAX_LINE_LENGTH, len(long_line))
        target = AnalysisTarget(0, [long_line, long_line], [1, 2], DUMMY_DESCRIPTOR)
        self.assertIsNone(MultiPattern.run(self.config, self.rule, target))

    def test_oversize_line_p(self) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        self.assertEqual(MAX_LINE_LENGTH, len(long_line))
        target = AnalysisTarget(0, [long_line, long_line], [1, 2], DUMMY_DESCRIPTOR)
        self.assertIsNotNone(MultiPattern.run(self.config, self.rule, target))
