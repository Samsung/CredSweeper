import unittest

from credsweeper.filters import ValueAzureTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueAzureTokenCheck(unittest.TestCase):

    def test_value_AzureToken_check_p(self):
        self.assertTrue(ValueAzureTokenCheck().run(get_line_data(line=""), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueAzureTokenCheck().run(get_line_data(line="eyJungle", pattern=LINE_VALUE_PATTERN),
                                                   DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueAzureTokenCheck().run(
            get_line_data(line="eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo", pattern=LINE_VALUE_PATTERN),
            DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueAzureTokenCheck().run(
            get_line_data(line="eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo.eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo"
                          ".eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))

    def test_value_AzureToken_check_n(self):
        self.assertFalse(ValueAzureTokenCheck().run(
            get_line_data(line="eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo.eyJpc3MiOjEsImV4cCI6MiwiaWF0IjozfQo"
                          ".1234567890qwertyuiopasdfghjklzxc",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
