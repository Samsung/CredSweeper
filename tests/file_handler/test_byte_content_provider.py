from typing import List

import pytest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.byte_content_provider import ByteContentProvider


class TestByteContentProvider:

    @pytest.mark.parametrize("lines_as_bytes,lines",
                             [(b"line one\npassword='in_line_2'", ["line one", "password='in_line_2'"])])
    def test_get_analysis_target_p(self, lines_as_bytes: bytes, lines: List[str]) -> None:
        """Evaluate that lines data correctly extracted from file"""
        content_provider = ByteContentProvider(lines_as_bytes)
        analysis_targets = content_provider.get_analysis_target()

        expected_target = AnalysisTarget(lines[0], 1, lines, "")

        assert len(analysis_targets) == 2

        target = analysis_targets[0]
        assert target == expected_target
