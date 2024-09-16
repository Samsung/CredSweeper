import re
from unittest import TestCase

from credsweeper.common.constants import Severity
from credsweeper.credentials import Candidate, LineData
from credsweeper.ml_model.features import SearchInAttribute, CharSet, WordInPath
from credsweeper.ml_model.features.has_html_tag import HasHtmlTag
from credsweeper.ml_model.features.is_secret_numeric import IsSecretNumeric
from credsweeper.ml_model.features.reny_entropy import RenyiEntropy
from credsweeper.ml_model.features.word_in_line import WordInLine
from credsweeper.ml_model.features.word_in_value import WordInValue
from tests import AZ_STRING

RE_TEST_PATTERN = re.compile(r"(?P<variable>.*) (?P<separator>over) (?P<value>.+)")


class TestFeatures(TestCase):

    def setUp(self):
        self.line_data = LineData(config=None,
                                  line=AZ_STRING,
                                  line_pos=0,
                                  line_num=1,
                                  path="path.ext",
                                  file_type="type",
                                  info="info",
                                  pattern=RE_TEST_PATTERN)

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

    def test_word_in_path_empty_n(self):
        self.line_data.path = ""
        self.assertListEqual([[0, 0, 0, 0]],
                             WordInPath(["dog", "lazy", "small",
                                         "the"])([Candidate([self.line_data], [], "rule", Severity.MEDIUM)]).tolist())

    def test_word_in_path_n(self):
        self.assertListEqual([[0, 0, 0, 0]],
                             WordInPath(["dog", "lazy", "small",
                                         "the"])([Candidate([self.line_data], [], "rule", Severity.MEDIUM)]).tolist())

    def test_word_in_path_p(self):
        self.assertListEqual([[1, 0, 0, 0]],
                             WordInPath([".ext", "lazy", "small",
                                         "the"])([Candidate([self.line_data], [], "rule", Severity.MEDIUM)]).tolist())

    def test_word_in_value_empty_n(self):
        self.line_data.value = ""
        self.assertListEqual([[0, 0, 0, 0]],
                             WordInValue(["aaa", "bbb", "ccc",
                                          "ddd"]).extract(Candidate([self.line_data], [], "rule",
                                                                    Severity.MEDIUM)).tolist())

    def test_word_in_value_n(self):
        self.assertListEqual([[0, 0, 0, 0]],
                             WordInValue(["aaa", "bbb", "ccc",
                                          "ddd"]).extract(Candidate([self.line_data], [], "rule",
                                                                    Severity.MEDIUM)).tolist())

    def test_word_in_value_p(self):
        self.assertListEqual([[1, 1, 0, 1]],
                             WordInValue(["dog", "lazy", "small",
                                          "the"]).extract(Candidate([self.line_data], [], "rule",
                                                                    Severity.MEDIUM)).tolist())

    def test_word_in_line_dup_n(self):
        with self.assertRaises(Exception):
            WordInLine(["fox", "fox"])

    def test_word_in_line_empty_n(self):
        self.line_data.line = ""
        self.line_data.value_start = 0
        test = WordInLine(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)).tolist())

    def test_word_in_line_n(self):
        test = WordInLine(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)).tolist())

    def test_word_in_line_p(self):
        test = WordInLine(["bear", "brown"])
        self.assertListEqual([[0, 1]], test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)).tolist())

    def test_has_html_tag_empty_n(self):
        self.line_data.line = ""
        self.line_data.value_start = 0
        test = HasHtmlTag()
        self.assertFalse(test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_has_html_tag_n(self):
        test = HasHtmlTag()
        self.assertFalse(test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_has_html_tag_p(self):
        test = HasHtmlTag()
        self.line_data.line = f"</br>{self.line_data.line}"
        self.assertTrue(test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
        self.line_data.line = f"<p>{self.line_data.line}</p>"
        self.assertTrue(test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_is_secret_numeric_empty_n(self):
        self.line_data.value = ""
        test = IsSecretNumeric()
        self.assertFalse(test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_is_secret_numeric_n(self):
        test = IsSecretNumeric()
        self.assertFalse(test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_is_secret_numeric_p(self):
        test = IsSecretNumeric()
        self.line_data.value = "2.718281828"
        self.assertTrue(test.extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_search_in_attribute_line_empty_n(self):
        self.line_data.line = ""
        self.assertFalse(
            SearchInAttribute("^the lazy dog$", "line").extract(Candidate([self.line_data], [], "rule",
                                                                          Severity.MEDIUM)))

    def test_search_in_attribute_variable_empty_n(self):
        self.line_data.variable = ""
        self.assertFalse(
            SearchInAttribute(".*dog", "variable").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
        self.line_data.variable = None
        self.assertFalse(
            SearchInAttribute(".*dog", "variable").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_search_in_attribute_value_empty_n(self):
        self.line_data.value = ""
        self.assertFalse(
            SearchInAttribute("fox", "value").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_search_in_attribute_n(self):
        self.assertFalse(
            SearchInAttribute("^the lazy dog$", "line").extract(Candidate([self.line_data], [], "rule",
                                                                          Severity.MEDIUM)))
        self.assertFalse(
            SearchInAttribute(".*dog", "variable").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
        self.assertFalse(
            SearchInAttribute("fox", "value").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_search_in_attribute_p(self):
        self.assertTrue(
            SearchInAttribute(".*the lazy dog$",
                              "line").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
        self.assertTrue(
            SearchInAttribute(".*fox", "variable").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
        self.assertTrue(
            SearchInAttribute("over", "separator").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
        self.assertTrue(
            SearchInAttribute("^the lazy dog$",
                              "value").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_char_set_empty_n(self):
        self.line_data.value = ""
        # just test to pass empty value - should be not happened in real
        self.assertTrue(CharSet("digits").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_char_set_n(self):
        self.assertFalse(CharSet("digits").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
        self.assertFalse(CharSet("ascii_lowercase").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))

    def test_char_set_p(self):
        self.line_data.value = self.line_data.value.replace(' ', '')
        self.assertTrue(CharSet("ascii_lowercase").extract(Candidate([self.line_data], [], "rule", Severity.MEDIUM)))
