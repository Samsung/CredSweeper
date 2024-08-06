import re
import unittest

from credsweeper.credentials import LineData
from credsweeper.filters import ValueBase64PartCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET


class TestValueBase64PartCheck(unittest.TestCase):
    EAA_PATTERN = re.compile(r"(?P<value>\bEAA[0-9A-Za-z]{32})")

    def test_value_check_n(self) -> None:
        line_data = LineData(config=None,
                             path="dummy",
                             file_type="",
                             line="qcE81rS+FJHuvg39lz4T/EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eo"
                             "se0cBAlGy7KeQ5Yna9CoDsup39tiYdoQ4jH9Coup39tiYdWoQ4jHFZD",
                             info="",
                             line_num=1,
                             line_pos=0,
                             pattern=TestValueBase64PartCheck.EAA_PATTERN)
        self.assertTrue(ValueBase64PartCheck().run(line_data, DUMMY_ANALYSIS_TARGET))

    def test_value_check_p(self) -> None:
        line_data = LineData(config=None,
                             path="dummy",
                             file_type="",
                             line="http://meta.test/api/EAACRvAWiwzR8rcXFsLiUH13ybj0tdEa?x=login",
                             info="",
                             line_num=1,
                             line_pos=0,
                             pattern=TestValueBase64PartCheck.EAA_PATTERN)
        self.assertFalse(ValueBase64PartCheck().run(line_data, DUMMY_ANALYSIS_TARGET))
