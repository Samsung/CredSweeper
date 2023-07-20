import unittest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.string_content_provider import StringContentProvider
from tests.filters.conftest import DUMMY_DESCRIPTOR


class TestStringContentProvider(unittest.TestCase):

    def test_get_analysis_target_p(self) -> None:
        """Evaluate that lines data correctly extracted from file"""
        lines = ["line one", "password='in_line_2'"]
        content_provider = StringContentProvider(lines)
        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]

        self.assertEqual(len(lines), len(analysis_targets))

        expected_target = AnalysisTarget(0, lines, [1, 2], DUMMY_DESCRIPTOR)
        self.assertEqual(expected_target.line, analysis_targets[0].line)
        # check second target and line numeration
        expected_target = AnalysisTarget(1, lines, [1, 2], DUMMY_DESCRIPTOR)
        self.assertEqual(expected_target.line, analysis_targets[1].line)

        # specific line numeration
        content_provider = StringContentProvider(lines, [42, -1])
        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]
        self.assertEqual(42, analysis_targets[0].line_num)
        self.assertEqual(-1, analysis_targets[1].line_num)

    def test_get_analysis_target_n(self) -> None:
        """Negative cases check"""
        # empty list
        content_provider = StringContentProvider([])
        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]
        self.assertEqual(0, len(analysis_targets))

        # mismatched amount of lists
        content_provider = StringContentProvider(["a", "b", "c"], [2, 3])
        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]
        self.assertEqual(3, len(analysis_targets))
        self.assertEqual(1, analysis_targets[0].line_num)
        self.assertEqual(2, analysis_targets[1].line_num)
        self.assertEqual(3, analysis_targets[2].line_num)

        content_provider = StringContentProvider(["a", "b", "c"], [5, 3, 4, 5])
        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]
        self.assertEqual(3, len(analysis_targets))
        self.assertEqual(1, analysis_targets[0].line_num)
        self.assertEqual(2, analysis_targets[1].line_num)
        self.assertEqual(3, analysis_targets[2].line_num)
