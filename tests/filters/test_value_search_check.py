import unittest

from credsweeper.filters import ValueSearchCheck
from tests import AZ_STRING
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueSearchCheck(unittest.TestCase):

    def test_value_search_check_n(self):
        line_data = get_line_data(line=AZ_STRING, pattern=LINE_VALUE_PATTERN)
        # None in constructor returns False always
        self.assertFalse(ValueSearchCheck().run(line_data, DUMMY_ANALYSIS_TARGET))
        # empty pattern - too
        self.assertFalse(ValueSearchCheck(pattern='').run(line_data, DUMMY_ANALYSIS_TARGET))
        # not the pattern. starts with capital letter
        self.assertFalse(ValueSearchCheck(pattern="^[a-z]").run(line_data, DUMMY_ANALYSIS_TARGET))

    def test_value_search_check_p(self):
        line_data = get_line_data(line=AZ_STRING, pattern=LINE_VALUE_PATTERN)
        # regex pattern
        self.assertTrue(ValueSearchCheck(pattern="^The( [a-z]+)+$").run(line_data, DUMMY_ANALYSIS_TARGET))
        # a word in value
        self.assertTrue(ValueSearchCheck(pattern="lazy").run(line_data, DUMMY_ANALYSIS_TARGET))
