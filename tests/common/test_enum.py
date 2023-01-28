import unittest

from credsweeper.common.constants import Severity


class TestEnum(unittest.TestCase):
    def test_severity_comparison_P(self):
        self.assertTrue(Severity.INFO < Severity.LOW)
        self.assertTrue(Severity.LOW < Severity.MEDIUM)
        self.assertTrue(Severity.MEDIUM < Severity.HIGH)
        self.assertTrue(Severity.HIGH < Severity.CRITICAL)

    def test_severity_comparison_N(self):
        self.assertFalse(Severity.CRITICAL < Severity.HIGH)
        self.assertFalse(Severity.HIGH < Severity.MEDIUM)
        self.assertFalse(Severity.MEDIUM < Severity.LOW)
        self.assertFalse(Severity.LOW < Severity.INFO)
