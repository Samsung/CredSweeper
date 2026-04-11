import re
import unittest

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValueSealedSecretCheck
from tests import AZ_STRING
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueSealedSecretCheck(unittest.TestCase):

    def test_value_search_check_n(self):
        line_data = get_line_data(line=AZ_STRING, pattern=LINE_VALUE_PATTERN)
        self.assertFalse(ValueSealedSecretCheck().run(line_data, DUMMY_ANALYSIS_TARGET))
        line_data = get_line_data(line="AQA", pattern=LINE_VALUE_PATTERN)
        self.assertFalse(ValueSealedSecretCheck().run(line_data, DUMMY_ANALYSIS_TARGET))
        line_data = get_line_data(line=f"AgA{'A' * MAX_LINE_LENGTH}", pattern=LINE_VALUE_PATTERN)
        self.assertFalse(ValueSealedSecretCheck().run(line_data, DUMMY_ANALYSIS_TARGET))

    def test_value_search_check_p(self):
        line = f"AgA{'A' * 1000}\nbitnami\nSealedSecret\nencryptedData\n"
        line_data = get_line_data(line=line, pattern=re.compile(r"(?P<value>\S+)"))
        target = AnalysisTarget(line_pos=0, lines=[line], line_nums=[1], descriptor=None)
        self.assertTrue(ValueSealedSecretCheck().run(line_data, target))
