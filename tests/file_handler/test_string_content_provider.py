from typing import List

import pytest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.string_content_provider import StringContentProvider


class TestStringContentProvider:

    @pytest.mark.parametrize("lines", [["line one", "password='in_line_2'"]])
    def test_get_analysis_target_p(self, lines: List[str]) -> None:
        """Evaluate that lines data correctly extracted from file"""
        content_provider = StringContentProvider(lines)
        analysis_targets = content_provider.get_analysis_target()

        expected_target = AnalysisTarget(lines[0], 1, lines, "", "", "")

        assert len(analysis_targets) == len(lines)

        target = analysis_targets[0]
        assert target == expected_target
