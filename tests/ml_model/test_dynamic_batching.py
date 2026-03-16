import unittest
from unittest.mock import Mock, patch, MagicMock
import numpy as np

from credsweeper.ml_model.ml_validator import MlValidator
from credsweeper.credentials.candidate import Candidate
from credsweeper.credentials.candidate_key import CandidateKey
from credsweeper.common.constants import ThresholdPreset


class TestDynamicBatching(unittest.TestCase):

    def setUp(self):
        with patch('credsweeper.ml_model.ml_validator.MlValidator._set_rules_scanners'):
            self.validator = MlValidator(
                threshold=0.5,
                min_batch_size=8,
                max_batch_size=512,
                memory_safety_margin=0.2
            )
        
        self.mock_candidates = []
        for i in range(20):
            mock_candidate = Mock(spec=Candidate)
            mock_candidate.use_ml = True
            mock_line_data = Mock()
            mock_line_data.line = f"password = 'secret{i}'"
            mock_line_data.variable = "password"
            mock_line_data.value = f"secret{i}"
            mock_line_data.value_start = 11
            mock_candidate.line_data_list = [mock_line_data]
            self.mock_candidates.append(mock_candidate)

    @patch.object(MlValidator, 'get_group_features')
    def test_calculate_optimal_batch_size_normal_memory(self, mock_get_features):
        mock_get_features.return_value = (
            np.zeros((1, 256, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 50))
        )
        
        with patch.object(self.validator.memory_monitor, 'get_available_memory_mb', return_value=1024):
            with patch.object(self.validator.memory_monitor, 'is_memory_pressure_high', return_value=False):
                batch_size = self.validator._calculate_optimal_batch_size(100)
                
                expected = int(1024 / 0.01)
                expected = min(512, max(8, expected))
                self.assertEqual(batch_size, 512)

    @patch.object(MlValidator, 'get_group_features')
    def test_calculate_optimal_batch_size_low_memory(self, mock_get_features):
        mock_get_features.return_value = (
            np.zeros((1, 256, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 50))
        )
        
        with patch.object(self.validator.memory_monitor, 'get_available_memory_mb', return_value=50):
            with patch.object(self.validator.memory_monitor, 'is_memory_pressure_high', return_value=False):
                batch_size = self.validator._calculate_optimal_batch_size(100)
                
                expected = int(50 / 0.01)
                expected = min(512, max(8, expected))
                self.assertEqual(batch_size, 500)

    @patch.object(MlValidator, 'get_group_features')
    def test_calculate_optimal_batch_size_memory_pressure(self, mock_get_features):
        mock_get_features.return_value = (
            np.zeros((1, 256, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 50))
        )
        
        with patch.object(self.validator.memory_monitor, 'get_available_memory_mb', return_value=1024):
            with patch.object(self.validator.memory_monitor, 'is_memory_pressure_high', return_value=True):
                batch_size = self.validator._calculate_optimal_batch_size(100)
                
                expected = int(1024 / 0.01)
                expected = min(512, max(8, expected))
                expected = max(8, expected // 2)
                self.assertEqual(batch_size, 256)

    def test_calculate_optimal_batch_size_no_memory(self):
        with patch.object(self.validator.memory_monitor, 'get_available_memory_mb', return_value=0):
            batch_size = self.validator._calculate_optimal_batch_size(100)
            self.assertEqual(batch_size, 8)

    @patch.object(MlValidator, 'get_group_features')
    def test_estimate_memory_per_candidate(self, mock_get_features):
        mock_get_features.return_value = (
            np.zeros((1, 256, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 50))
        )
        
        with patch.object(self.validator.memory_monitor, 'get_memory_info') as mock_get_memory:
            mock_before = Mock()
            mock_before.process_mb = 100.0
            mock_after = Mock()
            mock_after.process_mb = 100.5
            mock_get_memory.side_effect = [mock_before, mock_after]
            
            group_list = [(Mock(), self.mock_candidates[:4])]
            memory_per_candidate = self.validator._estimate_memory_per_candidate(group_list)
            
            self.assertEqual(memory_per_candidate, 0.125)
            self.assertEqual(self.validator.memory_per_candidate_mb, 0.125)

    @patch.object(MlValidator, '_estimate_memory_per_candidate')
    @patch.object(MlValidator, '_calculate_optimal_batch_size')
    @patch.object(MlValidator, '_batch_call_model')
    def test_validate_groups_dynamic_batching(self, mock_batch_call, mock_calc_batch, mock_estimate):
        mock_batch_call.return_value = np.array([0.8, 0.3, 0.9])
        mock_calc_batch.return_value = 16
        mock_estimate.return_value = 0.01
        
        group_list = [(Mock(), [candidate]) for candidate in self.mock_candidates[:3]]
        
        with patch.object(self.validator.memory_monitor, 'is_memory_pressure_high', return_value=False):
            is_cred, probability = self.validator.validate_groups(group_list)
            
            mock_estimate.assert_called_once()
            mock_calc_batch.assert_called_once_with(3)
            mock_batch_call.assert_called_once()
            
            self.assertEqual(len(is_cred), 3)
            self.assertEqual(len(probability), 3)
            self.assertTrue(all(is_cred[i] == (probability[i] >= 0.5) for i in range(3)))

    @patch.object(MlValidator, '_estimate_memory_per_candidate')
    @patch.object(MlValidator, '_calculate_optimal_batch_size')
    @patch.object(MlValidator, '_batch_call_model')
    def test_validate_groups_memory_pressure_adjustment(self, mock_batch_call, mock_calc_batch, mock_estimate):
        mock_batch_call.return_value = np.array([0.8, 0.3])
        mock_calc_batch.side_effect = [16, 8]
        mock_estimate.return_value = 0.01
        
        group_list = [(Mock(), [candidate]) for candidate in self.mock_candidates[:4]]
        
        with patch.object(self.validator.memory_monitor, 'is_memory_pressure_high') as mock_pressure:
            with patch.object(self.validator.memory_monitor, 'force_garbage_collection') as mock_gc:
                mock_pressure.side_effect = [False, True]
                
                is_cred, probability = self.validator.validate_groups(group_list)
                
                mock_gc.assert_called_once()
                self.assertEqual(mock_calc_batch.call_count, 2)

    def test_validate_groups_fixed_batch_size(self):
        with patch.object(self.validator, '_estimate_memory_per_candidate') as mock_estimate:
            with patch.object(self.validator, '_calculate_optimal_batch_size') as mock_calc:
                with patch.object(self.validator, '_batch_call_model') as mock_batch:
                    mock_batch.return_value = np.array([0.8, 0.3])
                    mock_estimate.return_value = 0.01
                    mock_calc.return_value = 16
                    
                    group_list = [(Mock(), [candidate]) for candidate in self.mock_candidates[:2]]
                    
                    is_cred, probability = self.validator.validate_groups(group_list, batch_size=32)
                    
                    mock_estimate.assert_not_called()
                    mock_calc.assert_not_called()
                    mock_batch.assert_called_once()


if __name__ == '__main__':
    unittest.main()
