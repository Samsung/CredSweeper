import re
import unittest

from credsweeper.credentials.line_data import LineData
from credsweeper.filters.value_basic_auth_check import ValueBasicAuthCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET


class TestValueBasicAuthCheck(unittest.TestCase):

    def test_value_check_n(self) -> None:
        for value in [
                "VGhlVXNlcjtUaGVQYXM1dzByZA==",  #
                "Programming_Language",  #
        ]:
            line_data = LineData(config=None,
                                 path="dummy",
                                 file_type="",
                                 line=value,
                                 info="",
                                 line_num=1,
                                 line_pos=0,
                                 pattern=re.compile(fr"(?P<value>{value})"))
            self.assertTrue(ValueBasicAuthCheck().run(line_data, DUMMY_ANALYSIS_TARGET), value)

    def test_value_check_p(self) -> None:
        for value in [
                "VGhlVXNlcjpUaGVQYXM1dzByZA==",  #
        ]:
            line_data = LineData(config=None,
                                 path="dummy",
                                 file_type="",
                                 line=value,
                                 info="",
                                 line_num=1,
                                 line_pos=0,
                                 pattern=re.compile(fr"(?P<value>{value})"))
            self.assertFalse(ValueBasicAuthCheck().run(line_data, DUMMY_ANALYSIS_TARGET), value)
