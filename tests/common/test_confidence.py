import unittest

from credsweeper.common.constants import Confidence


class TestConfidence(unittest.TestCase):

    def test_severity_p(self):
        self.assertEqual(Confidence.MODERATE, Confidence.get(Confidence.MODERATE))
        self.assertEqual(Confidence.WEAK, Confidence.get("WeaK"))
        self.assertEqual(Confidence.MODERATE, Confidence.get("MODERATE"))
        self.assertEqual(Confidence.STRONG, Confidence.get("strong"))

    def test_severity_n(self):
        self.assertIsNone(Confidence.get(None))
        self.assertIsNone(Confidence.get(1))
        self.assertIsNone(Confidence.get([1, 2, 3]))
        self.assertIsNone(Confidence.get({1, 2, 3}))
        self.assertIsNone(Confidence.get("None"))
        self.assertIsNone(Confidence.get("HI-GH"))
        self.assertIsNone(Confidence.get(" HI GH "))

    def test_severity_comparison_p(self):
        self.assertTrue(Confidence.WEAK < Confidence.MODERATE)
        self.assertTrue(Confidence.WEAK < Confidence.STRONG)
        self.assertTrue(Confidence.MODERATE < Confidence.STRONG)
        test_list = [Confidence.MODERATE, Confidence.STRONG, Confidence.WEAK]
        test_list.sort()
        self.assertListEqual([Confidence.WEAK, Confidence.MODERATE, Confidence.STRONG], test_list)

    def test_severity_comparison_n(self):
        self.assertFalse(Confidence.MODERATE < Confidence.WEAK)
        self.assertFalse(Confidence.WEAK > Confidence.MODERATE)
        self.assertFalse(Confidence.WEAK > Confidence.STRONG)
        self.assertFalse(Confidence.MODERATE > Confidence.STRONG)
