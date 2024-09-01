import re
from unittest import TestCase

from credsweeper.common.constants import Severity
from credsweeper.credentials import Candidate, LineData
from credsweeper.ml_model.features import MatchInAttribute
from credsweeper.ml_model.features.has_html_tag import HasHtmlTag
from credsweeper.ml_model.features.is_secret_numeric import IsSecretNumeric
from credsweeper.ml_model.features.reny_entropy import RenyiEntropy
from credsweeper.ml_model.features.word_in_line import WordInLine
from credsweeper.ml_model.features.word_in_value import WordInValue
from tests import AZ_STRING

RE_TEST_PATTERN = re.compile(r"(?P<variable>.*) (?P<separator>over) (?P<value>.+)")


class TestFeatures(TestCase):

    def test_renyi_entropy_p(self):
        test_entropy = RenyiEntropy('hex', 0, norm=True)
        probabilities = test_entropy.get_probabilities(AZ_STRING)
        print(probabilities)
        assert len(probabilities) == 6
        expected_max = [0.12500001, 0.12500001, 0.12500001, 0.12500001, 0.37500001, 0.12500001]
        expected_min = [0.12499999, 0.12499999, 0.12499999, 0.12499999, 0.37499999, 0.12499999]
        for n in range(6):
            self.assertLess(expected_min[n], probabilities[n], f"probabilities[{n}]")
            self.assertGreater(expected_max[n], probabilities[n], f"probabilities[{n}]")

    def test_renyi_entropy_n(self):
        test_entropy = RenyiEntropy('hex', 0, norm=False)
        probabilities = test_entropy.get_probabilities(AZ_STRING)
        print(probabilities)
        assert len(probabilities) == 6
        expected_max = [0.024, 0.024, 0.024, 0.024, 0.07, 0.024]
        expected_min = [0.023, 0.023, 0.023, 0.023, 0.06, 0.023]
        for n in range(6):
            self.assertLess(expected_min[n], probabilities[n], f"probabilities[{n}]")
            self.assertGreater(expected_max[n], probabilities[n], f"probabilities[{n}]")

    def test_estimate_entropy_n(self):
        test_entropy = RenyiEntropy('hex', 0)
        self.assertEqual(0.0, test_entropy.estimate_entropy([]))

    def test_estimate_entropy_p(self):
        test_entropy = RenyiEntropy('base64', 0)
        probabilities = test_entropy.get_probabilities(AZ_STRING)
        self.assertEqual(4.754887502163468, test_entropy.estimate_entropy(probabilities))

    def test_word_in_value_p(self):
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=RE_TEST_PATTERN)
        self.assertListEqual([[1, 1, 0, 1]],
                             WordInValue(["dog", "lazy", "small",
                                          "the"]).extract(Candidate([ld], [], "rule", Severity.MEDIUM)).tolist())

    def test_word_in_value_n(self):
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=RE_TEST_PATTERN)
        self.assertListEqual([[0, 0]],
                             WordInValue(["pink", "quick"]).extract(Candidate([ld], [], "rule",
                                                                              Severity.MEDIUM)).tolist())

    def test_word_in_line_n(self):
        test = WordInLine(["text"])
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=RE_TEST_PATTERN)
        self.assertListEqual([[0]], test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)).tolist())

    def test_has_html_tag_n(self):
        test = HasHtmlTag()
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=RE_TEST_PATTERN)
        self.assertFalse(test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)))

    def test_is_secret_numeric_n(self):
        test = IsSecretNumeric()
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=RE_TEST_PATTERN)
        self.assertFalse(test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)))

    def test_match_in_attribute_n(self):
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=RE_TEST_PATTERN)
        self.assertFalse(MatchInAttribute(".*dog", "variable").extract(Candidate([ld], [], "rule", Severity.MEDIUM)))
        self.assertFalse(MatchInAttribute("fox", "value").extract(Candidate([ld], [], "rule", Severity.MEDIUM)))
        self.assertFalse(MatchInAttribute("lazy dog", "line").extract(Candidate([ld], [], "rule", Severity.MEDIUM)))

    def test_match_in_attribute_p(self):
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=RE_TEST_PATTERN)
        self.assertTrue(MatchInAttribute(".*fox", "variable").extract(Candidate([ld], [], "rule", Severity.MEDIUM)))
        self.assertTrue(MatchInAttribute("over", "separator").extract(Candidate([ld], [], "rule", Severity.MEDIUM)))
        self.assertTrue(
            MatchInAttribute("^the lazy dog$", "value").extract(Candidate([ld], [], "rule", Severity.MEDIUM)))
