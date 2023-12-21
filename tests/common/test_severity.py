import unittest

from credsweeper.common.constants import Severity


class TestSeverity(unittest.TestCase):

    def test_severity_p(self):
        self.assertEqual(Severity.MEDIUM, Severity.get(Severity.MEDIUM))
        self.assertEqual(Severity.INFO, Severity.get("inFo"))
        self.assertEqual(Severity.LOW, Severity.get("LoW"))
        self.assertEqual(Severity.MEDIUM, Severity.get("MEDIUM"))
        self.assertEqual(Severity.HIGH, Severity.get("    HIGH  "))
        self.assertEqual(Severity.CRITICAL, Severity.get("critical"))

    def test_severity_n(self):
        self.assertIsNone(Severity.get(None))
        self.assertIsNone(Severity.get(1))
        self.assertIsNone(Severity.get([1, 2, 3]))
        self.assertIsNone(Severity.get({1, 2, 3}))
        self.assertIsNone(Severity.get("None"))
        self.assertIsNone(Severity.get("HI-GH"))
        self.assertIsNone(Severity.get(" HI GH "))

    def test_severity_comparison_p(self):
        self.assertTrue(Severity.INFO < Severity.LOW)
        self.assertTrue(Severity.INFO < Severity.MEDIUM)
        self.assertTrue(Severity.INFO < Severity.HIGH)
        self.assertTrue(Severity.INFO < Severity.CRITICAL)

        self.assertTrue(Severity.LOW < Severity.MEDIUM)
        self.assertTrue(Severity.LOW < Severity.HIGH)
        self.assertTrue(Severity.LOW < Severity.CRITICAL)

        self.assertTrue(Severity.MEDIUM < Severity.HIGH)
        self.assertTrue(Severity.MEDIUM < Severity.CRITICAL)

        self.assertTrue(Severity.HIGH < Severity.CRITICAL)

    def test_severity_comparison_n(self):
        self.assertFalse(Severity.CRITICAL < Severity.HIGH)
        self.assertFalse(Severity.HIGH < Severity.MEDIUM)
        self.assertFalse(Severity.MEDIUM < Severity.LOW)
        self.assertFalse(Severity.LOW < Severity.INFO)

        self.assertFalse(Severity.INFO > Severity.LOW)
        self.assertFalse(Severity.INFO > Severity.MEDIUM)
        self.assertFalse(Severity.INFO > Severity.HIGH)
        self.assertFalse(Severity.INFO > Severity.CRITICAL)

        self.assertFalse(Severity.LOW > Severity.MEDIUM)
        self.assertFalse(Severity.LOW > Severity.HIGH)
        self.assertFalse(Severity.LOW > Severity.CRITICAL)

        self.assertFalse(Severity.MEDIUM > Severity.HIGH)
        self.assertFalse(Severity.MEDIUM > Severity.CRITICAL)

        self.assertFalse(Severity.HIGH > Severity.CRITICAL)
