import re
from unittest import TestCase

from credsweeper.app import APP_PATH
from credsweeper.common.constants import Severity, MAX_LINE_LENGTH
from credsweeper.credentials import Candidate, LineData
from credsweeper.ml_model.features import SearchInAttribute, WordInPath, MorphemeDense, EntropyEvaluation, \
    LengthOfAttribute, WordInLine
from credsweeper.ml_model.features.has_html_tag import HasHtmlTag
from credsweeper.ml_model.features.is_secret_numeric import IsSecretNumeric
from credsweeper.ml_model.features.word_in_value import WordInValue
from credsweeper.utils import Util
from tests import AZ_STRING

RE_TEST_PATTERN = re.compile(r"quick (?P<variable>brown fox) jumps (?P<separator>over) (?P<value>the lazy) dog")


class TestFeatures(TestCase):

    @staticmethod
    def init_feature_search_comment(comment: str) -> SearchInAttribute:
        feature = None
        model_config = Util.json_load(APP_PATH / "ml_model" / "ml_config.json")
        for fet in model_config["features"]:
            if "SearchInAttribute" == fet["type"] and comment == fet.get("comment", ''):
                assert feature is None, f"check duplication of '{comment}'"
                feature = SearchInAttribute(**fet["kwargs"])
        else:
            assert feature is not None, f"missed SearchInAttribute for '{comment}'"
        return feature

    def setUp(self):
        self.maxDiff = None
        self.model_config = Util.json_load(APP_PATH / "ml_model" / "ml_config.json")
        self.line_data = LineData(
            config=None,
            line=AZ_STRING,
            line_pos=0,
            line_num=1,
            path="src/path.ext",  # looks like after glob
            file_type=".ext",
            info="info",
            pattern=RE_TEST_PATTERN)
        self.candidate = Candidate(line_data_list=[self.line_data],
                                   patterns=[],
                                   rule_name="rule",
                                   severity=Severity.MEDIUM)

    def test_entropy_evaluation_n(self):
        feature = EntropyEvaluation()
        candidate = self.candidate
        self.line_data.value = "\0\0\0"
        self.assertListEqual([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
                             feature.extract(candidate).tolist())

    def test_entropy_evaluation_p(self):
        feature = EntropyEvaluation()
        candidate = self.candidate
        extracted1 = feature.extract(candidate).tolist()
        self.assertListEqual([1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
                             extracted1)
        self.line_data.value = "bace4d19-fa7e-beef-cafe-9129474bcd81"
        extracted2 = feature.extract(candidate).tolist()
        self.assertListEqual([
            0.7041769027709961, 0.6943118572235107, 0.6783386468887329, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
            1.0, 0.0, 0.0, 1.0, 1.0
        ], extracted2)

    def test_length_attribute_unsupported_n(self):
        with self.assertRaises(Exception):
            LengthOfAttribute("separator")

    def test_length_attribute_empty_n(self):
        feature = LengthOfAttribute("line")
        candidate = self.candidate
        self.line_data.line = ''
        self.assertListEqual([0.0], feature.extract(candidate).tolist())

    def test_length_attribute_oversize_n(self):
        feature = LengthOfAttribute("line")
        candidate = self.candidate
        self.line_data.line = ' ' * MAX_LINE_LENGTH
        self.assertListEqual([1.0], feature.extract(candidate).tolist())

    def test_length_attribute_p(self):
        feature = LengthOfAttribute("value")
        candidate = self.candidate
        self.assertListEqual([0.09876543209876543], feature.extract(candidate).tolist())

    def test_word_in_path_empty_n(self):
        self.line_data.path = ""
        self.assertListEqual([[0, 0, 0, 0]], WordInPath(["dog", "lazy", "small", "the"])([self.candidate]).tolist())

    def test_word_in_path_n(self):
        self.assertListEqual([[0, 0, 0, 0]], WordInPath(["dog", "lazy", "small", "the"])([self.candidate]).tolist())

    def test_word_in_path_p(self):
        self.assertListEqual([[1, 1, 0, 0]], WordInPath(["/src", "/path", "small", "the"])([self.candidate]).tolist())

    def test_word_in_value_empty_n(self):
        self.line_data.value = ""
        self.assertListEqual([[0, 0, 0, 0]], WordInValue(["aaa", "bbb", "ccc", "ddd"]).extract(self.candidate).tolist())

    def test_word_in_value_n(self):
        self.assertListEqual([[0, 0, 0, 0]], WordInValue(["aaa", "bbb", "ccc", "ddd"]).extract(self.candidate).tolist())

    def test_word_in_value_p(self):
        self.assertListEqual([[0, 1, 0, 1]],
                             WordInValue(["the", "small", "lazy", "dog"]).extract(self.candidate).tolist())

    def test_word_in_line_dup_n(self):
        with self.assertRaises(Exception):
            WordInLine(["fox", "fox"])

    def test_word_in_line_empty_n(self):
        self.line_data.line = ""
        self.line_data.value_start = 0
        test = WordInLine(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_line_n(self):
        test = WordInLine(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_line_p(self):
        test = WordInLine(["bear", "brown"])
        self.assertListEqual([[0, 1]], test.extract(self.candidate).tolist())

    def test_has_html_tag_empty_n(self):
        self.line_data.line = ""
        self.line_data.value_start = 0
        test = HasHtmlTag()
        self.assertFalse(test.extract(self.candidate))

    def test_has_html_tag_n(self):
        test = HasHtmlTag()
        self.assertFalse(test.extract(self.candidate))

    def test_has_html_tag_p(self):
        test = HasHtmlTag()
        self.line_data.line = f"</br>{self.line_data.line}"
        self.assertTrue(test.extract(self.candidate))
        self.line_data.line = f"<p>{self.line_data.line}</p>"
        self.assertTrue(test.extract(self.candidate))

    def test_is_secret_numeric_empty_n(self):
        self.line_data.value = ""
        test = IsSecretNumeric()
        self.assertFalse(test.extract(self.candidate))

    def test_is_secret_numeric_n(self):
        test = IsSecretNumeric()
        self.assertFalse(test.extract(self.candidate))

    def test_is_secret_numeric_p(self):
        test = IsSecretNumeric()
        self.line_data.value = "2.718281828"
        self.assertTrue(test.extract(self.candidate))

    def test_search_in_attribute_line_empty_n(self):
        self.line_data.line = ""
        self.assertFalse(SearchInAttribute("^the lazy dog$", "line").extract(self.candidate))

    def test_search_in_attribute_variable_empty_n(self):
        self.line_data.variable = ""
        self.assertFalse(SearchInAttribute(".*dog", "variable").extract(self.candidate))
        self.line_data.variable = None
        self.assertFalse(SearchInAttribute(".*dog", "variable").extract(self.candidate))

    def test_search_in_attribute_value_empty_n(self):
        self.line_data.value = ""
        self.assertFalse(SearchInAttribute("fox", "value").extract(self.candidate))

    def test_search_in_attribute_n(self):
        self.assertFalse(SearchInAttribute("^the lazy dog$", "line").extract(self.candidate))
        self.assertFalse(SearchInAttribute(".*dog", "variable").extract(self.candidate))
        self.assertFalse(SearchInAttribute("fox", "value").extract(self.candidate))

    def test_search_in_attribute_p(self):
        self.assertTrue(SearchInAttribute(".*the lazy dog$", "line").extract(self.candidate))
        self.assertTrue(SearchInAttribute(".*fox", "variable").extract(self.candidate))
        self.assertTrue(SearchInAttribute("over", "separator").extract(self.candidate))
        self.assertTrue(SearchInAttribute("^the lazy$", "value").extract(self.candidate))

    def test_morpheme_dense_n(self):
        self.line_data.value = ""
        self.assertEqual(0, MorphemeDense().extract(self.candidate))
        self.line_data.value = "ZaQ1@wSxCdE3$rFvbGt56yhNmJu7*ik"
        self.assertEqual(0, MorphemeDense().extract(self.candidate))

    def test_morpheme_dense_p(self):
        self.assertEqual(0.75, MorphemeDense().extract(self.candidate))
        self.line_data.value = "KeyApiPasswordToken"
        self.assertEqual(0.9473684210526315, MorphemeDense().extract(self.candidate))
