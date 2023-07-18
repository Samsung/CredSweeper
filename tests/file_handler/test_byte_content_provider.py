import os
from typing import List

import pytest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.utils import Util
from tests import SAMPLES_FILES_COUNT, SAMPLES_PATH
from tests.filters.conftest import DUMMY_DESCRIPTOR


class TestByteContentProvider:

    @pytest.mark.parametrize("lines_as_bytes,lines",
                             [(b"line one\npassword='in_line_2'", ["line one", "password='in_line_2'"])])
    def test_get_analysis_target_p(self, lines_as_bytes: bytes, lines: List[str]) -> None:
        """Evaluate that lines data correctly extracted from file"""
        content_provider = ByteContentProvider(lines_as_bytes)
        analysis_targets = [x for x in content_provider.yield_analysis_target()]

        expected_target = AnalysisTarget(0, lines, [x for x in range(len(lines))], DUMMY_DESCRIPTOR)

        assert len(analysis_targets) == 2

        target = analysis_targets[0]
        assert target.line == expected_target.line

    def test_byte_content_provider_p(self) -> None:
        files_counter = 0
        for dir_path, _, filenames in os.walk(SAMPLES_PATH):
            filenames.sort()
            for filename in filenames:
                files_counter += 1
                file_path = os.path.join(dir_path, filename)
                util_text = Util.read_file(file_path)
                with open(file_path, 'rb') as f:
                    bin_data = f.read()
                provider = ByteContentProvider(bin_data)
                assert util_text == provider.lines
        assert files_counter == SAMPLES_FILES_COUNT
