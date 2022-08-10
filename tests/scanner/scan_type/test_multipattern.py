import random
import string
import unittest
from unittest.mock import patch

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.scanner.scan_type import MultiPattern


class TestMultiPattern(unittest.TestCase):

    def test_oversize_line_n(self) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        long_line += 'OVERSIZE'
        self.assertLess(MAX_LINE_LENGTH, len(long_line))
        with patch('logging.Logger.warning') as mock_warning:
            self.assertFalse(MultiPattern.is_valid_line_length(long_line))
            mock_warning.assert_called_once()

    def test_oversize_line_p(self) -> None:
        long_line: str = ''.join(random.choices(string.ascii_letters, k=MAX_LINE_LENGTH))
        self.assertEqual(MAX_LINE_LENGTH, len(long_line))
        with patch('logging.Logger.warning') as mock_warning:
            self.assertTrue(MultiPattern.is_valid_line_length(long_line))
            mock_warning.assert_not_called()
