import copy
import unittest
from unittest.mock import patch

from credsweeper.credentials import LineData, Candidate
from credsweeper.credentials.augment_candidates import augment_candidates
from tests import AZ_STRING


class TestAugmentCandidates(unittest.TestCase):

    def test_augment_candidates_p(self):
        with patch.object(LineData, LineData.initialize.__name__):
            candidate = Candidate.get_dummy_candidate(None, "file_path", "file_type", "info")
            candidate.line_data_list[0].value = AZ_STRING
            candidates = [candidate]
            additional_candidates = copy.deepcopy(candidates)
            # the value is different
            additional_candidates[0].line_data_list[0].value = f"\"{AZ_STRING}\""
            # additional candidates must be added
            augment_candidates(candidates, additional_candidates)
            self.assertEqual(2, len(candidates))
            self.assertEqual(AZ_STRING, candidates[0].line_data_list[0].value)
            self.assertEqual(f"\"{AZ_STRING}\"", candidates[1].line_data_list[0].value)

    def test_augment_candidates_n(self):
        with patch.object(LineData, LineData.initialize.__name__):
            candidate = Candidate.get_dummy_candidate(None, "file_path", "file_type", "info")
            candidate.line_data_list[0].value = AZ_STRING
            candidates = [candidate]

            # empty additional candidates
            augment_candidates(candidates, [])
            self.assertEqual(1, len(candidates))

            # the same value
            augment_candidates(candidates, copy.deepcopy(candidates))
            self.assertEqual(1, len(candidates))

            self.assertEqual(AZ_STRING, candidates[0].line_data_list[0].value)
