import os
import string
import unittest
import random
from typing import List

import pytest

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.utils import Util
from tests import SAMPLES_FILES_COUNT


class TestByteContentProvider(unittest.TestCase):

    def test_get_analysis_target_p(self) -> None:
        """Evaluate that lines data correctly extracted from file"""
        data: bytes = bytearray()
        data += b"line one\r"
        data += b"password='in_line_2'\n"
        data += b"line3\r\n"
        # will produce 2 lines in sequence \n\r
        data += b"line4\n\r"
        data += b"EOF"
        content_provider = ByteContentProvider(data)
        analysis_targets = content_provider.get_analysis_target()
        lines = ["line one", "password='in_line_2'", "line3", "line4", "", "EOF"]
        expected_target = AnalysisTarget(lines[0], 1, lines, "")

        assert len(analysis_targets) == 6, analysis_targets
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
        assert files_counter == SAMPLES_FILES_COUNT

    def test_multiline_p(self) -> None:
        line_data: bytes = bytearray()
        line_data += b'\\\r\na\\\nb\\\nc\\\n'
        line_data += bytearray(ord(random.choice(string.ascii_uppercase)) for _ in range(MAX_LINE_LENGTH))
        # add line split character which is over limit but without - it will be valid line
        line_data += b'\\\n1\\\r2\\\n3\\\r\n'
        # ASCII from ` to o
        line_data += bytearray(ord(random.choice(string.ascii_lowercase)) for _ in range(MAX_LINE_LENGTH))
        # add line split character which is over limit but without - it will be valid line
        line_data += b'OVERSIZED\\\nA\\\nB\\\nC\\'
        provider = ByteContentProvider(line_data)
        # Should be split to 12 lines
        self.assertEqual(12, len(provider.lines), provider.lines)
        # each line ends with linewrap
        for line in provider.lines:
            self.assertEqual('\\', line[-1:], line)
        targets = provider.lines_to_targets(provider.lines)
        self.assertEqual(5, len(targets))
        self.assertEqual('abc', targets[0].line)
        self.assertEqual(1, targets[0].line_num)
        self.assertEqual('123', targets[2].line)
        self.assertEqual(6, targets[2].line_num)
        self.assertEqual('ABC', targets[4].line)
        self.assertEqual(10, targets[4].line_num)
