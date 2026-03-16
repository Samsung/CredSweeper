import unittest
from unittest.mock import Mock, patch
import numpy as np

from credsweeper.app import CredSweeper
from credsweeper.credentials.candidate import Candidate
from credsweeper.credentials.credential_manager import CredentialManager
from credsweeper.credentials.candidate_key import CandidateKey


class TestIntegration(unittest.TestCase):

    def setUp(self):
        with patch('credsweeper.app.Scanner'), \
             patch('credsweeper.app.DeepScanner'), \
             patch('credsweeper.app.CredentialManager'):
            self.credsweeper = CredSweeper(
                pool_count=1,
                ml_batch_size=16,
                ml_threshold=0.5
            )

    @patch.object(CredSweeper, 'ml_validator')
    def test_ml_validator_initialization(self, mock_ml_validator):
        mock_validator_instance = Mock()
        mock_ml_validator.return_value = mock_validator_instance
        
        validator = self.credsweeper.ml_validator
        
        mock_ml_validator.assert_called_once()
        args, kwargs = mock_ml_validator.call_args
        self.assertEqual(kwargs['min_batch_size'], 4)
        self.assertEqual(kwargs['max_batch_size'], 64)
        self.assertEqual(kwargs['memory_safety_margin'], 0.2)

    @patch.object(CredSweeper, 'ml_validator')
    @patch.object(CredSweeper, '_use_ml_validation', return_value=True)
    def test_post_processing_with_dynamic_batching(self, mock_use_ml, mock_ml_validator):
        mock_validator_instance = Mock()
        mock_validator_instance.validate_groups.return_value = (
            np.array([True, False, True]),
            np.array([0.8, 0.3, 0.9])
        )
        mock_ml_validator.return_value = mock_validator_instance
        
        mock_candidate1 = Mock(spec=Candidate)
        mock_candidate1.use_ml = True
        mock_candidate1.line_data_list = [Mock()]
        
        mock_candidate2 = Mock(spec=Candidate)
        mock_candidate2.use_ml = True
        mock_candidate2.line_data_list = [Mock()]
        
        mock_candidate3 = Mock(spec=Candidate)
        mock_candidate3.use_ml = True
        mock_candidate3.line_data_list = [Mock()]
        
        self.credsweeper.credential_manager.candidates = [mock_candidate1, mock_candidate2, mock_candidate3]
        self.credsweeper.credential_manager.group_credentials.return_value = {
            Mock(): [mock_candidate1],
            Mock(): [mock_candidate2],
            Mock(): [mock_candidate3]
        }
        
        self.credsweeper.post_processing()
        
        mock_validator_instance.validate_groups.assert_called_once()
        call_args = mock_validator_instance.validate_groups.call_args
        self.assertEqual(len(call_args[0][0]), 3)
        self.assertIsNone(call_args[1].get('batch_size'))

    @patch.object(CredSweeper, 'ml_validator')
    @patch.object(CredSweeper, '_use_ml_validation', return_value=False)
    def test_post_processing_skip_ml(self, mock_use_ml, mock_ml_validator):
        mock_candidate = Mock(spec=Candidate)
        mock_candidate.use_ml = False
        self.credsweeper.credential_manager.candidates = [mock_candidate]
        
        self.credsweeper.post_processing()
        
        mock_ml_validator.assert_not_called()


if __name__ == '__main__':
    unittest.main()
