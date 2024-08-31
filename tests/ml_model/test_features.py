from unittest import TestCase

from credsweeper.common.constants import Severity, KeywordPattern
from credsweeper.credentials import Candidate, LineData
from credsweeper.ml_model.features.has_html_tag import HasHtmlTag
from credsweeper.ml_model.features.is_secret_numeric import IsSecretNumeric
from credsweeper.ml_model.features.possible_comment import PossibleComment
from credsweeper.ml_model.features.reny_entropy import RenyiEntropy
from credsweeper.ml_model.features.word_in_line import WordInLine
from credsweeper.ml_model.features.word_in_value import WordInValue
from tests import AZ_STRING


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
        test = WordInValue(["fox", "dog"])
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=KeywordPattern.get_keyword_pattern("password"))
        ld.value = AZ_STRING
        self.assertListEqual([1,1], test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)).tolist())

    def test_word_in_value_n(self):
        test = WordInValue(["bear"])
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=KeywordPattern.get_keyword_pattern("password"))
        ld.value = ""
        self.assertListEqual([0], test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)).tolist())

    def test_word_in_line_n(self):
        test = WordInLine(["text"])
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=KeywordPattern.get_keyword_pattern("password"))
        self.assertListEqual([0], test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)).tolist())

    def test_has_html_tag_n(self):
        test = HasHtmlTag()
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=KeywordPattern.get_keyword_pattern("password"))
        self.assertFalse(test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)))

    def test_possible_comment_n(self):
        test = PossibleComment()
        ld = LineData(config=None,
                      line=AZ_STRING,
                      line_pos=0,
                      line_num=1,
                      path="path",
                      file_type="type",
                      info="info",
                      pattern=KeywordPattern.get_keyword_pattern("password"))
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
                      pattern=KeywordPattern.get_keyword_pattern("password"))
        ld.value = 'dummy'
        self.assertFalse(test.extract(Candidate([ld], [], "rule", Severity.MEDIUM)))
