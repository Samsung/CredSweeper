import random
import string
import unittest
from unittest import mock
from unittest.mock import Mock

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.scanner.scan_type import MultiPattern


class TestMultiPattern(unittest.TestCase):

    @mock.patch("logging.warning")
    def test_oversize_line_n(self, mock_warning: Mock(return_value=None)) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        long_line += 'OVERSIZE'
        self.assertLess(MAX_LINE_LENGTH, len(long_line))
        self.assertFalse(MultiPattern.is_valid_line_length(long_line))
        self.assertTrue(mock_warning.called)
        self.assertEqual(1, mock_warning.call_count)

    @mock.patch("logging.warning")
    def test_oversize_line_p(self, mock_warning: Mock(return_value=None)) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        self.assertEqual(MAX_LINE_LENGTH, len(long_line))
        self.assertTrue(MultiPattern.is_valid_line_length(long_line))
        self.assertFalse(mock_warning.called)
