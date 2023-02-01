from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.utils import DiffRowData, DiffDict


class TestDiffContentProvider:

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
                "new": 3,
                "line": "moved line",
                "hunk": 1
            })
        ]
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        analysis_targets = content_provider.get_analysis_target()

        all_lines = ["", "new line", "moved line"]
        expected_target = AnalysisTarget("new line", 2, all_lines, file_path, ".file", DiffRowType.ADDED.value)

        assert len(analysis_targets) == 1

        target = analysis_targets[0]
        assert target == expected_target

    def test_get_analysis_target_n(self) -> None:
        """Evaluate that deleted diff lines data correctly filtered for added change type"""
        file_path = "dumy.file"
        diff = [{
            "old": 2,
            "new": None,
            "line": "new line",
            "hunk": 1
        }, {
            "old": 3,
            "new": 2,
            "line": "moved line",
            "hunk": 1
        }]
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        analysis_targets = content_provider.get_analysis_target()

        assert len(analysis_targets) == 0

    def test_parse_lines_data_p(self) -> None:
        """Evaluate that added diff lines data correctly added to change_numbers"""
        file_path = "dumy.file"
        diff = []
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        lines_data = [DiffRowData(DiffRowType.ADDED, 2, "new line")]

        change_numbs, _all_lines = content_provider.parse_lines_data(lines_data)

        expected_numbs = [2]

        assert change_numbs == expected_numbs

    def test_parse_lines_data_n(self) -> None:
        """Evaluate that deleted diff lines data correctly filtered for added change type"""
        file_path = "dumy.file"
        diff = []
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        lines_data = [DiffRowData(DiffRowType.DELETED, 2, "old line")]

        change_numbs, _all_lines = content_provider.parse_lines_data(lines_data)

        expected_numbs = []

        assert change_numbs == expected_numbs

    def test_accompany_parse_lines_data_p(self) -> None:
        """Evaluate that added diff lines data correctly added to all_lines"""
        file_path = "dumy.file"
        diff = []
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        lines_data = [DiffRowData(DiffRowType.ADDED_ACCOMPANY, 2, "new line")]

        _change_numbs, all_lines = content_provider.parse_lines_data(lines_data)

        expected_lines = ["", "new line"]

        assert all_lines == expected_lines

    def test_accompany_parse_lines_data_n(self) -> None:
        """Evaluate that deleted diff lines data correctly filtered for added change type"""
        file_path = "dumy.file"
        diff = []
        content_provider = DiffContentProvider(file_path, DiffRowType.ADDED, diff)

        lines_data = [DiffRowData(DiffRowType.ADDED_ACCOMPANY, 2, "new ine")]

        change_numbs, _all_lines = content_provider.parse_lines_data(lines_data)

        expected_numbs = []

        assert change_numbs == expected_numbs
