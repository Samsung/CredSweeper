from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.string_content_provider import StringContentProvider


class TestStringContentProvider:

    def test_get_analysis_target_p(self) -> None:
        """Evaluate that lines data correctly extracted from file"""
        lines = ["line one", "password='in_line_2'"]
        content_provider = StringContentProvider(lines)
        analysis_targets = content_provider.get_analysis_target()

        assert len(analysis_targets) == len(lines)

        expected_target = AnalysisTarget(lines[0], 1, lines, "", "", "")
        assert analysis_targets[0] == expected_target
        # check second target and line numeration
        expected_target = AnalysisTarget(lines[1], 2, lines, "", "", "")
        assert analysis_targets[1] == expected_target

        # specific line numeration
        content_provider = StringContentProvider(lines, [42, -1])
        analysis_targets = content_provider.get_analysis_target()
        assert analysis_targets[0].line_num == 42
        assert analysis_targets[1].line_num == -1

    def test_get_analysis_target_n(self) -> None:
        """Negative cases check"""
        # empty list
        content_provider = StringContentProvider([])
        analysis_targets = content_provider.get_analysis_target()
        assert len(analysis_targets) == 0

        # mismatched amount of lists
        content_provider = StringContentProvider(["a", "b", "c"], [2, 3])
        analysis_targets = content_provider.get_analysis_target()
        assert len(analysis_targets) == 3
        assert analysis_targets[0].line_num == 1
        assert analysis_targets[1].line_num == 2
        assert analysis_targets[2].line_num == 3

        content_provider = StringContentProvider(["a", "b", "c"], [5, 3, 4, 5])
        analysis_targets = content_provider.get_analysis_target()
        assert len(analysis_targets) == 3
        assert analysis_targets[0].line_num == 1
        assert analysis_targets[1].line_num == 2
        assert analysis_targets[2].line_num == 3
