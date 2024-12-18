import copy
import re
import unittest
from typing import Tuple

import numpy as np

from credsweeper import ThresholdPreset
from credsweeper.app import APP_PATH
from credsweeper.common.constants import Severity, MAX_LINE_LENGTH, MIN_DATA_LEN
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CandidateKey, LineData
from credsweeper.ml_model import MlValidator
from credsweeper.utils import Util
from tests import NEGLIGIBLE_ML_THRESHOLD, AZ_STRING


class TestMlValidator(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.ml_validator = MlValidator(threshold=ThresholdPreset.medium)
        assert self.ml_validator is not None
        file_name = APP_PATH / "secret" / "config.json"
        config_dict = Util.json_load(file_name)
        config_dict["use_filters"] = True
        config_dict["find_by_ext"] = False
        config_dict["depth"] = 0
        config_dict["doc"] = False
        config_dict["find_by_ext_list"] = []
        config_dict["size_limit"] = None
        self.config = Config(config_dict)

    def validate(self, _candidate: Candidate) -> Tuple[bool, float]:
        """Validate single credential candidate."""
        candidate_key = CandidateKey(_candidate.line_data_list[0])
        sample_as_batch = [(candidate_key, [_candidate])]
        is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 1)
        return is_cred_batch[0], probability_batch[0]

    def test_ml_validator_simple_n(self):
        candidate = Candidate.get_dummy_candidate(self.config, "main.py", ".py", "info")
        candidate.rule_name = "Password"
        candidate.line_data_list[0].line = 'password="Ahga%$FiQ@Ei8"'
        candidate.line_data_list[0].variable = "password"
        candidate.line_data_list[0].value_start = 16
        candidate.line_data_list[0].value_end = 25
        candidate.line_data_list[0].value = "Ahga%$FiQ@Ei8"

        decision, probability = self.validate(candidate)
        self.assertAlmostEqual(0.9997878074645996, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

        candidate.line_data_list[0].path = "sample.yaml"
        candidate.line_data_list[0].file_type = ".yaml"
        decision, probability = self.validate(candidate)
        self.assertAlmostEqual(0.9989185333251953, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

        candidate.line_data_list[0].path = "test.zip"
        candidate.line_data_list[0].file_type = ".zip"
        decision, probability = self.validate(candidate)
        self.assertAlmostEqual(0.9992884397506714, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

        candidate.line_data_list[0].path = "other.txt"
        candidate.line_data_list[0].file_type = ".txt"
        decision, probability = self.validate(candidate)
        self.assertAlmostEqual(0.9963308572769165, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

    def test_ml_validator_auxiliary_p(self):
        candidate = Candidate.get_dummy_candidate(self.config, "mycred", "", "")
        candidate.rule_name = "Secret"
        candidate.line_data_list[0].line = "secret=238475614782"
        candidate.line_data_list[0].variable = "secret"
        candidate.line_data_list[0].value_start = 7
        candidate.line_data_list[0].value_end = 43
        candidate.line_data_list[0].value = "238475614782"
        # auxiliary candidate for a pattern rule - without variable
        aux_candidate = copy.deepcopy(candidate)
        aux_candidate.line_data_list[0].variable = None

        # todo: the scores are low for current ML model - will be changed after train

        candidate_key = CandidateKey(candidate.line_data_list[0])
        sample_as_batch = [(candidate_key, [candidate])]
        is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 2)
        self.assertAlmostEqual(0.989341139793396, probability_batch[0], delta=NEGLIGIBLE_ML_THRESHOLD)

        # auxiliary rule which was not trained - keeps the same ML probability
        aux_candidate.rule_name = "PASSWD_PAIR"
        sample_as_batch = [(candidate_key, [candidate, aux_candidate])]
        is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 2)
        self.assertAlmostEqual(0.989341139793396, probability_batch[0], delta=NEGLIGIBLE_ML_THRESHOLD)

        # auxiliary rule in train increases ML probability
        aux_candidate.rule_name = "Token"
        is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 2)
        self.assertAlmostEqual(0.9856619834899902, probability_batch[0], delta=NEGLIGIBLE_ML_THRESHOLD)

        # which real line may be
        candidate.line_data_list[0].line = "secret=func(token=238475614782)"
        aux_candidate.line_data_list[0].line = "secret=func(token=238475614782)"
        aux_candidate.line_data_list[0].variable = "token"
        is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 2)
        self.assertAlmostEqual(0.9185001850128174, probability_batch[0], delta=NEGLIGIBLE_ML_THRESHOLD)

    def test_ml_validator_auxiliary_n(self):
        candidate = Candidate.get_dummy_candidate(self.config, "secret", "", "")
        candidate.rule_name = "Secret"
        candidate.line_data_list[0].line = "secret=bace4d19-dead-beef-cafe-9129474bcd81"
        candidate.line_data_list[0].variable = "secret"
        candidate.line_data_list[0].value_start = 7
        candidate.line_data_list[0].value_end = 43
        candidate.line_data_list[0].value = "bace4d19-dead-beef-cafe-9129474bcd81"
        # auxiliary candidate for a pattern rule - without variable
        aux_candidate = copy.deepcopy(candidate)
        aux_candidate.line_data_list[0].variable = None

        # todo: the scores are low for current ML model - will be changed after train

        candidate_key = CandidateKey(candidate.line_data_list[0])
        sample_as_batch = [(candidate_key, [candidate])]
        is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 2)
        self.assertAlmostEqual(0.9983870387077332, probability_batch[0], delta=NEGLIGIBLE_ML_THRESHOLD)

        # auxiliary rule in train does not increase ML probability yet - will be used after next train

        aux_candidate.rule_name = "UUID"
        sample_as_batch = [(candidate_key, [candidate, aux_candidate])]
        is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 2)
        self.assertAlmostEqual(0.9983870387077332, probability_batch[0], delta=NEGLIGIBLE_ML_THRESHOLD)

    def test_extract_features_n(self):
        candidate1 = Candidate.get_dummy_candidate(self.config, "___.x3", ".x3", "")
        candidate1.line_data_list[0].line = ''
        candidate1.line_data_list[0].variable = ''
        candidate1.line_data_list[0].value_start = 0
        candidate1.line_data_list[0].value_end = 0
        candidate1.line_data_list[0].value = ''
        candidate1.rule_name = ''
        features1 = self.ml_validator.extract_features([candidate1])
        self.assertEqual(0, np.count_nonzero(features1))

    def test_extract_features_p(self):
        candidate1 = Candidate.get_dummy_candidate(self.config, "???.py", ".py", "")
        candidate1.line_data_list[0].line = '??????????????????????????'
        candidate1.line_data_list[0].variable = "???????"
        candidate1.line_data_list[0].value_start = 2
        candidate1.line_data_list[0].value_end = 6
        candidate1.line_data_list[0].value = "???????????????????"
        candidate1.rule_name = "???????"
        features1_1 = self.ml_validator.extract_features([candidate1])

        self.assertEqual(6, np.count_nonzero(features1_1))
        candidate1.rule_name = "Password"
        features1_1 = self.ml_validator.extract_features([candidate1])
        self.assertEqual(7, np.count_nonzero(features1_1))
        candidate1.line_data_list[0].value = "example/"
        features1_2 = self.ml_validator.extract_features([candidate1])
        self.assertEqual(14, np.count_nonzero(features1_2))
        candidate1.line_data_list[0].value = "undefined/"
        features1_3 = self.ml_validator.extract_features([candidate1])
        self.assertEqual(14, np.count_nonzero(features1_3))
        candidate1.line_data_list[0].value = "undefined/example"
        features1_4 = self.ml_validator.extract_features([candidate1])
        self.assertEqual(15, np.count_nonzero(features1_4))

        candidate2 = copy.deepcopy(candidate1)
        candidate2.rule_name = "UNKNOWN RULE"
        features2 = self.ml_validator.extract_features([candidate1, candidate2])
        self.assertEqual(15, np.count_nonzero(features2))
        candidate2.rule_name = "Secret"
        features3 = self.ml_validator.extract_features([candidate1, candidate2])
        self.assertEqual(15 + 1, np.count_nonzero(features3))

    def testVariableNotAllowedPatternCheck_n(self):
        candidate1 = Candidate.get_dummy_candidate(self.config, "???.py", ".py", "")
        candidate1.line_data_list[0].line = '?????????????:!!!!!!!!!!!!!'
        candidate1.line_data_list[0].variable = "?????????????"
        candidate1.line_data_list[0].value_start = 14
        candidate1.line_data_list[0].value_end = 27
        candidate1.line_data_list[0].value = "!!!!!!!!!!!!!"
        candidate1.rule_name = "##########"
        features1_1 = self.ml_validator.extract_features([candidate1])

        self.assertEqual(6, np.count_nonzero(features1_1))
        candidate1.line_data_list[0].variable = "pub_key"
        features1_2 = self.ml_validator.extract_features([candidate1])
        self.assertEqual(7, np.count_nonzero(features1_2))

    def test_extract_features_normalized_n(self):
        line_data = LineData(config=self.config,
                             line=AZ_STRING,
                             line_pos=0,
                             line_num=1,
                             path="path.ext",
                             file_type="type",
                             info="info",
                             pattern=re.compile(r"(?P<variable>.*) (?P<separator>over) (?P<value>.+)"))
        candidate = Candidate([line_data], [], "rule", Severity.MEDIUM)
        features = self.ml_validator.extract_features([candidate])
        self.assertLess(0, np.count_nonzero(features))
        for i in features.tolist()[0]:
            self.assertLessEqual(0.0, i)
            self.assertGreaterEqual(1.0, i)

    def test_encode_n(self):
        self.assertEqual(0, np.count_nonzero(self.ml_validator.encode(None, 0)))
        self.assertEqual(0, np.count_nonzero(self.ml_validator.encode("", 10)))
        self.assertEqual(0, np.count_nonzero(self.ml_validator.encode("AAA", 0)))

    def test_encode_p(self):
        self.assertEqual(MIN_DATA_LEN, np.count_nonzero(self.ml_validator.encode(AZ_STRING, MIN_DATA_LEN)))
        self.assertEqual(len(AZ_STRING), np.count_nonzero(self.ml_validator.encode(AZ_STRING, MAX_LINE_LENGTH)))
        self.assertEqual(7, np.count_nonzero(self.ml_validator.encode("\xFE\xFF \n\t`\0", MIN_DATA_LEN)))
        self.assertEqual(
            [[
                0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
            ],
             [
                 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
             ],
             [
                 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
             ],
             [
                 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
             ],
             [
                 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
             ],
             [
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
             ],
             [
                 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
             ],
             [
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
             ]],
            self.ml_validator.encode("\xFE\xFF \n\t`\0", MIN_DATA_LEN).tolist())
