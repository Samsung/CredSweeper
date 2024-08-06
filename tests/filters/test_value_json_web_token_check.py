import unittest

from credsweeper.filters import ValueJsonWebTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueJsonWebTokenCheck(unittest.TestCase):

    def test_value_jwt_check_p(self):
        self.assertTrue(ValueJsonWebTokenCheck().run(get_line_data(line="", pattern=LINE_VALUE_PATTERN),
                                                     DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(get_line_data(line="eyJungle", pattern=LINE_VALUE_PATTERN),
                                                     DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="1234567890qwertyuiopasdfghjklzxc", pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.eyJleHAiOjY1NTM2fQo",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.65474687468446387653",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))

    def test_value_jwt_check_n(self):
        self.assertFalse(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.0xm2jd8ha7zo3l5qn48",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
