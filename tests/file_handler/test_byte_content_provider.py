import os
from typing import List

import pytest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.utils import Util


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

    def test_byte_content_provider_p(self) -> None:
        files_counter = 0
        dir_path = os.path.dirname(os.path.realpath(__file__))
        tests_path = os.path.join(dir_path, "..", "samples")
        for dir_path, _, filenames in os.walk(tests_path):
            filenames.sort()
            for filename in filenames:
                files_counter += 1
                file_path = os.path.join(dir_path, filename)
                util_text = Util.read_file(file_path)
                with open(file_path, 'rb') as f:
                    bin_data = f.read()
                provider = ByteContentProvider(bin_data)
                assert util_text == provider.lines
        assert files_counter == 39
