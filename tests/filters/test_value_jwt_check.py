import unittest

from credsweeper.filters import ValueJwtCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueJwtCheck(unittest.TestCase):

    def test_value_jwt_check_p(self):
        self.assertTrue(ValueJwtCheck().run(get_line_data(line="eyJungle", pattern=LINE_VALUE_PATTERN),
                                            DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJwtCheck().run(
            get_line_data(line="1234567890qwertyuiopasdfghjklzxc", pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))

    def test_value_jwt_check_n(self):
        self.assertFalse(ValueJwtCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.1234567890qwertyuiopasdfghjklzxc",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertFalse(ValueJwtCheck().run(
            get_line_data(line="1234567890qwertyuiopasdfghjklzxc.1234567890qwertyuiopasdfghjklzxc",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))

    def test_value_jwt_check_empty_value_n(self) -> None:
        line_data = get_line_data(line="")
        assert ValueJwtCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
