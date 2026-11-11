import unittest

from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.diff_content_provider import DiffContentProvider, DiffDict, DiffRowData


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
        self.assertEqual(2, len(provider.diff))
        provider.free()
        self.assertEqual(0, len(provider.diff))
        provider.free()
        provider.free()

    def test_data_n(self) -> None:
        with self.assertRaises(NotImplementedError):
            _ = DiffContentProvider("file_path", DiffRowType.ADDED, []).data

    def test_patch2files_diff_same_file_p(self) -> None:
        """Evaluate that changes of the same file from several patches in one series are all kept"""
        raw_patch = [
            "diff --git a/c.py b/c.py",
            "index 1111111..2222222 100644",
            "--- a/c.py",
            "+++ b/c.py",
            "@@ -1,3 +1,3 @@",
            " x = 1",
            "-x = 2",
            "+first_added",
            " x = 3",
            "diff --git a/c.py b/c.py",
            "index 2222222..3333333 100644",
            "--- a/c.py",
            "+++ b/c.py",
            "@@ -28,3 +28,3 @@",
            " x = 28",
            "-x = 29",
            "+second_added",
            " x = 30",
        ]
        added = DiffContentProvider.patch2files_diff(raw_patch, DiffRowType.ADDED)
        self.assertListEqual(["c.py"], list(added.keys()))
        added_lines = [x["line"] for x in added["c.py"] if x["old"] is None]
        self.assertListEqual(["first_added", "second_added"], added_lines)
        deleted = DiffContentProvider.patch2files_diff(raw_patch, DiffRowType.DELETED)
        self.assertListEqual(["c.py"], list(deleted.keys()))
        deleted_lines = [x["line"] for x in deleted["c.py"] if x["new"] is None]
        self.assertListEqual(["x = 2", "x = 29"], deleted_lines)
