import re
from unittest import TestCase

from credsweeper.app import APP_PATH
from credsweeper.common.constants import Severity, MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate, LineData
from credsweeper.ml_model.features.distance import Distance
from credsweeper.ml_model.features.entropy_evaluation import EntropyEvaluation
from credsweeper.ml_model.features.file_extension import FileExtension
from credsweeper.ml_model.features.has_html_tag import HasHtmlTag
from credsweeper.ml_model.features.is_secret_numeric import IsSecretNumeric
from credsweeper.ml_model.features.length_of_attribute import LengthOfAttribute
from credsweeper.ml_model.features.morpheme_dense import MorphemeDense
from credsweeper.ml_model.features.rule_name import RuleName
from credsweeper.ml_model.features.rule_severity import RuleSeverity
from credsweeper.ml_model.features.search_in_attribute import SearchInAttribute
from credsweeper.ml_model.features.word_in_path import WordInPath
from credsweeper.ml_model.features.word_in_postamble import WordInPostamble
from credsweeper.ml_model.features.word_in_preamble import WordInPreamble
from credsweeper.ml_model.features.word_in_transition import WordInTransition
from credsweeper.ml_model.features.word_in_value import WordInValue
from credsweeper.ml_model.features.word_in_variable import WordInVariable
from credsweeper.utils.util import Util
from tests import AZ_STRING

RE_TEST_PATTERN = re.compile(r"quick (?P<variable>brown fox) jumps (?P<separator>over) (?P<value>the lazy) dog")


class TestFeatures(TestCase):

    @staticmethod
    def init_feature_search_comment(comment: str) -> SearchInAttribute:
        feature = None
        model_config = Util.json_load(APP_PATH / "ml_model" / "ml_config.json")
        for feat in model_config["features"]:
            if "SearchInAttribute" == feat["type"] and comment == feat.get("comment", ''):
                assert feature is None, f"check duplication of '{comment}'"
                feature = SearchInAttribute(**feat["kwargs"])
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

    def test_distance_n(self):
        feature = Distance()
        self.candidate.line_data_list[0].variable = None
        self.assertEqual(0.0, feature.extract(self.candidate))

    def test_distance_p(self):
        feature = Distance()
        self.candidate.line_data_list[0].variable = "PASSWORD_CONFIRMATION_TAG"
        self.candidate.line_data_list[0].value = "testPassConfirmTag"
        self.assertEqual(0.6511627906976745, feature.extract(self.candidate))
        self.candidate.line_data_list[0].variable = "SALT"
        self.candidate.line_data_list[0].value = "5a17"
        self.assertEqual(0.25, feature.extract(self.candidate))
        self.candidate.line_data_list[0].variable = "secret"
        self.candidate.line_data_list[0].value = "s239777e586c38rbe197t9"
        self.assertEqual(0.42857142857142855, feature.extract(self.candidate))
        self.candidate.line_data_list[0].variable = "s239777e586c38rbe197t9"
        self.candidate.line_data_list[0].value = "secret"
        self.assertEqual(0.42857142857142855, feature.extract(self.candidate))

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

    def test_file_extension_n(self):
        self.assertListEqual([[0, 0, 0]], FileExtension([".txt", ".doc", ".exe"])([self.candidate]).tolist())

    def test_file_extension_p(self):
        self.assertListEqual([[0, 0, 1]], FileExtension([".0", ".abc", ".ext"])([self.candidate]).tolist())

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
        self.line_data.value = None
        self.assertListEqual([[0, 0, 0, 0]], WordInValue(["aaa", "bbb", "ccc", "ddd"]).extract(self.candidate).tolist())

    def test_word_in_value_n(self):
        self.assertListEqual([[0, 0, 0, 0]], WordInValue(["aaa", "bbb", "ccc", "ddd"]).extract(self.candidate).tolist())

    def test_word_in_value_p(self):
        self.assertListEqual([[0, 1, 0, 1]],
                             WordInValue(["the", "small", "lazy", "dog"]).extract(self.candidate).tolist())

    def test_word_in_variable_empty_n(self):
        self.line_data.variable = None
        self.assertListEqual([[0, 0, 0, 0]],
                             WordInVariable(["aaa", "bbb", "ccc", "ddd"]).extract(self.candidate).tolist())

    def test_word_in_variable_n(self):
        self.assertListEqual([[0, 0, 0, 0]],
                             WordInVariable(["aaa", "bbb", "ccc", "ddd"]).extract(self.candidate).tolist())

    def test_word_in_variable_p(self):
        self.assertListEqual([[1, 1, 0, 0]],
                             WordInVariable(["brown", "fox", "lazy", "the"]).extract(self.candidate).tolist())

    def test_word_in_preamble_dup_n(self):
        with self.assertRaises(Exception):
            WordInPreamble(["fox", "fox"])

    def test_word_in_preamble_empty_n(self):
        self.line_data.line = ""
        self.line_data.value_start = 0
        test = WordInPreamble(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_preamble_n(self):
        test = WordInPreamble(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_preamble_p(self):
        test = WordInPreamble(["dog", "the"])
        self.assertListEqual([[0, 1]], test.extract(self.candidate).tolist())

    def test_word_in_transition_dup_n(self):
        with self.assertRaises(Exception):
            WordInTransition(["fox", "fox"])

    def test_word_in_transition_empty_n(self):
        self.line_data.line = ""
        self.line_data.value_start = 0
        test = WordInTransition(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_transition_n(self):
        test = WordInTransition(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_transition_p(self):
        test = WordInTransition(["fox", "jumps"])
        self.assertListEqual([[0, 1]], test.extract(self.candidate).tolist())

    def test_word_in_postamble_dup_n(self):
        with self.assertRaises(Exception):
            WordInPostamble(["dog", "dog"])

    def test_word_in_postamble_empty_n(self):
        self.line_data.line = ""
        self.line_data.value_start = 0
        test = WordInPostamble(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_postamble_n(self):
        test = WordInPostamble(["dummy", "text"])
        self.assertListEqual([[0, 0]], test.extract(self.candidate).tolist())

    def test_word_in_postamble_p(self):
        test = WordInPostamble(["dog", "fox"])
        self.assertListEqual([[1, 0]], test.extract(self.candidate).tolist())

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
        self.line_data.value = "2e+64"
        self.assertTrue(test.extract(self.candidate))
        self.line_data.value = "2.718281828"
        self.assertTrue(test.extract(self.candidate))
        self.line_data.value = "-0.5"
        self.assertTrue(test.extract(self.candidate))
        self.line_data.value = ".33"
        self.assertTrue(test.extract(self.candidate))
        self.line_data.value = "+.33e-2"
        self.assertTrue(test.extract(self.candidate))
        self.line_data.value = "0xdeadbeef"
        self.assertTrue(test.extract(self.candidate))
        self.line_data.value = "0xDeadBeefCafeBabe"
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
        self.line_data.value = "5A1T"
        self.assertEqual(0, MorphemeDense().extract(self.candidate))
        self.line_data.value = "ZaQ1@wSxCdE3$rFvbGt56yhNmJu7*ik"
        self.assertEqual(0, MorphemeDense().extract(self.candidate))

    def test_morpheme_dense_p(self):
        self.assertEqual(0.875, MorphemeDense().extract(self.candidate))
        self.line_data.value = "KeyApiPasswordToken"
        self.assertEqual(1.0, MorphemeDense().extract(self.candidate))
        self.line_data.value = "salt:saltSALTsalt"
        self.assertEqual(0.9411764705882353, MorphemeDense().extract(self.candidate))
        self.line_data.value = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        self.assertEqual(1.0, MorphemeDense().extract(self.candidate))

    def test_rule_name_n(self):
        self.assertListEqual([[0, 0]], RuleName(["dummy", "test"])([self.candidate]).tolist())

    def test_rule_name_p(self):
        self.assertListEqual([[0, 1]], RuleName(["mock", "rule"])([self.candidate]).tolist())

    COMMENT_STYLES = [
        "camelStyle naming detection",
        "PascalStyle naming detection",
        "UPPERCASE naming detection",
        "lowercase naming detection",
    ]
    STYLES_MAP = {
        "": None,  #
        "iii111oooXoooXoo": None,  #
        "n0tCamlStyle23": None,  #
        "notCam3lStyle23": None,  #
        "NotPa5calStyle": None,  #
        "__n0t_example_some_name_in_code_4__example": None,  #
        "_N0T_EXAMPLE_WR0NG_": None,  #
        "__MAIN__": None,  #
        "___SLAVE": None,  #
        "NOTEXAMPLE": None,  #
        "4_EXAMPLE_NOT_VAR": None,  #
        "PascalStyle": "PascalStyle naming detection",  #
        "Pascal33Style": "PascalStyle naming detection",  #
        "PascalX86Style": "PascalStyle naming detection",  #
        "camelStyle": "camelStyle naming detection",  #
        "testCamelStyle1": "camelStyle naming detection",  #
        "test23Camel43Style65": "camelStyle naming detection",  #
        "camelX86Style": "camelStyle naming detection",  #
        "_MY_X86_DEMO_VAR": "UPPERCASE naming detection",  #
        "_42_YOU_VAR": "UPPERCASE naming detection",  #
        "_4_YOU_": "UPPERCASE naming detection",  #
        "_H204__U_": "UPPERCASE naming detection",  #
        "_AARCH64_X86_FLUCTUATOR": "UPPERCASE naming detection",  #
        "EXAMPLE_IS_VAR": "UPPERCASE naming detection",  #
        "EXAMPLE__VAR": "UPPERCASE naming detection",  #
        "some_name_in_code": "lowercase naming detection",  #
        "___some_name_in_code_4__example": "lowercase naming detection",  #
    }

    def test_style_n(self):
        candidate = self.candidate
        for comment in self.COMMENT_STYLES:
            feature = self.init_feature_search_comment(comment)
            for val, typ in self.STYLES_MAP.items():
                if typ is None or typ != comment:
                    candidate.line_data_list[0].value = val
                    self.assertFalse(feature.extract(candidate), (comment, typ, val))

    def test_style_p(self):
        candidate = self.candidate
        for comment in self.COMMENT_STYLES:
            feature = self.init_feature_search_comment(comment)
            for val, typ in self.STYLES_MAP.items():
                if typ == comment:
                    candidate.line_data_list[0].value = val
                    self.assertTrue(feature.extract(candidate), (comment, typ, val))

    def test_rule_severity_n(self):
        self.candidate.severity = Severity.INFO
        self.assertEqual(0.0, RuleSeverity().extract(self.candidate))
        self.candidate.severity = None
        with self.assertRaises(ValueError):
            RuleSeverity().extract(self.candidate)

    def test_rule_severity_p(self):
        self.line_data.value = ""
        self.assertEqual(0.5, RuleSeverity().extract(self.candidate))
        self.candidate.severity = Severity.CRITICAL
        self.assertEqual(1.0, RuleSeverity().extract(self.candidate))
