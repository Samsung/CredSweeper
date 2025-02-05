import unittest

from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.utils import DiffRowData, DiffDict


class TestDiffContentProvider(unittest.TestCase):

    def test_get_analysis_target_p(self) -> None:
        """Evaluate that added diff lines data correctly added to change_numbers"""
        file_path = "dumy.file"
        diff = [
            DiffDict({
                "old": None,
                "new": 2,
                "line": "new line",
                "hunk": 1
            }),
            DiffDict({
                "old": 2,
                "new": None,
                "line": "moved line",
                "hunk": 1
            })
        ]
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]

        all_lines = ["", "new line", "moved line"]
        expected_target = AnalysisTarget(1, all_lines, [x for x in range(len(all_lines))],
                                         Descriptor(file_path, ".file", DiffRowType.ADDED.value))

        self.assertEqual(1, len(analysis_targets))

        target = analysis_targets[0]
        self.assertEqual(expected_target.line, target.line)

    def test_get_analysis_target_n(self) -> None:
        """Evaluate that deleted diff lines data correctly filtered for added change type"""
        file_path = "dumy.file"
        diff = [
            DiffDict({
                "old": 2,
                "new": None,
                "line": "new line",
                "hunk": 1
            }),
            DiffDict({
                "old": 3,
                "new": None,
                "line": "moved line",
                "hunk": 1
            })
        ]
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]

        self.assertEqual(0, len(analysis_targets))

    def test_parse_lines_data_p(self) -> None:
        """Evaluate that added diff lines data correctly added to change_numbers"""
        lines_data = [DiffRowData(DiffRowType.ADDED, 2, "new line")]

        change_numbs, _all_lines = DiffContentProvider.parse_lines_data(DiffRowType.ADDED, lines_data)

        expected_numbs = [2]

        self.assertListEqual(expected_numbs, change_numbs)

    def test_parse_lines_data_n(self) -> None:
        """Evaluate that deleted diff lines data correctly filtered for added change type"""
        lines_data = [DiffRowData(DiffRowType.DELETED, 2, "old line")]

        change_numbs, _all_lines = DiffContentProvider.parse_lines_data(DiffRowType.ADDED, lines_data)

        expected_numbs = []

        self.assertListEqual(expected_numbs, change_numbs)

    def test_free_n(self) -> None:
        diff = [
            DiffDict({
                "old": 2,
                "new": None,
                "line": "new line",
                "hunk": 1
            }),
            DiffDict({
                "old": 3,
                "new": None,
                "line": "moved line",
                "hunk": 1
            })
        ]
        provider = DiffContentProvider("file_path", DiffRowType.ADDED, diff)
        provider.free()
        self.assertIsNone(provider.diff)
