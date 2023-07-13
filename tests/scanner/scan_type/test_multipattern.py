import random
import string
import unittest
from unittest.mock import MagicMock

from credsweeper.common.constants import MAX_LINE_LENGTH, SourceType
from credsweeper.config import Config
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import MultiPattern


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
                "type": "pattern",
                "doc_availabel": False,
                "values": ["a", "b"],
                "filter_type": [],
                "min_line_len": 0,
            })

    def test_oversize_line_n(self) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        long_line += 'OVERSIZE'
        self.assertLess(MAX_LINE_LENGTH, len(long_line))
        target = AnalysisTarget(long_line, 1, [long_line, long_line])
        self.assertIsNone(MultiPattern.run(self.config, self.rule, target))

    def test_oversize_line_p(self) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        self.assertEqual(MAX_LINE_LENGTH, len(long_line))
        target = AnalysisTarget(long_line, 1, [long_line, long_line])
        self.assertIsNotNone(MultiPattern.run(self.config, self.rule, target))
