import unittest
from unittest.mock import Mock, patch
import numpy as np

class MockCredSweeper:
    def __init__(self):
        self.ml_batch_size = 16
        self.ml_threshold = 0.5
        self.ml_config = None
        self.ml_model = None
        self.ml_providers = None
        self.__ml_validator = None

    @property
    def ml_validator(self):
        if not self.__ml_validator:
            mock_validator = Mock()
            mock_validator.validate_groups.return_value = (
                np.array([True, False, True]),
                np.array([0.8, 0.3, 0.9])
            )
            self.__ml_validator = mock_validator
        return self.__ml_validator

    def _use_ml_validation(self):
        return True
    
    def post_processing(self):
        if not hasattr(self, 'credential_manager'):
            return
            
        if self.credential_manager.purge_duplicates():
            pass
            
        if self._use_ml_validation():
            if self.credential_manager.candidates:
                cred_groups = self.credential_manager.group_credentials()
                ml_cred_groups = []
                
                for group_key, group_candidates in cred_groups.items():
                    for candidate in group_candidates:
                        if candidate.use_ml:
                            ml_cred_groups.append((group_key, group_candidates))
                            break
                    else:
                        pass
                
                if ml_cred_groups:
                    is_cred, probability = self.ml_validator.validate_groups(ml_cred_groups)
                    new_cred_list = []
                    
                    for i, (_, group_candidates) in enumerate(ml_cred_groups):
                        for candidate in group_candidates:
                            if candidate.use_ml:
                                if is_cred[i]:
                                    candidate.ml_probability = probability[i]
                                    new_cred_list.append(candidate)
                            else:
                                new_cred_list.append(candidate)
                    
                    self.credential_manager.set_credentials(new_cred_list)


class TestIntegration(unittest.TestCase):

    def setUp(self):
        self.credsweeper = MockCredSweeper()

    def test_ml_validator_initialization(self):
        validator = self.credsweeper.ml_validator
        self.assertIsNotNone(validator)

    def test_post_processing_with_dynamic_batching(self):
        mock_candidate1 = Mock()
        mock_candidate1.use_ml = True
        mock_candidate1.line_data_list = [Mock()]
        
        mock_candidate2 = Mock()
        mock_candidate2.use_ml = True
        mock_candidate2.line_data_list = [Mock()]
        
        mock_candidate3 = Mock()
        mock_candidate3.use_ml = True
        mock_candidate3.line_data_list = [Mock()]
        
        mock_manager = Mock()
        mock_manager.candidates = [mock_candidate1, mock_candidate2, mock_candidate3]
        mock_manager.group_credentials.return_value = {
            Mock(): [mock_candidate1],
            Mock(): [mock_candidate2],
            Mock(): [mock_candidate3]
        }
        mock_manager.purge_duplicates.return_value = 0
        mock_manager.set_credentials = Mock()
        mock_manager.get_credentials.return_value = []
        
        self.credsweeper.credential_manager = mock_manager
        
        self.credsweeper.post_processing()
        
        self.credsweeper.ml_validator.validate_groups.assert_called_once()
        call_args = self.credsweeper.ml_validator.validate_groups.call_args
        self.assertEqual(len(call_args[0][0]), 3)

    def test_post_processing_skip_ml(self):
        mock_candidate = Mock()
        mock_candidate.use_ml = False
        
        mock_manager = Mock()
        mock_manager.candidates = [mock_candidate]
        mock_manager.purge_duplicates.return_value = 0
        mock_manager.set_credentials = Mock()
        mock_manager.get_credentials.return_value = []
        
        self.credsweeper.credential_manager = mock_manager
        self.credsweeper._use_ml_validation = lambda: False
        
        self.credsweeper.post_processing()
        
        self.credsweeper.ml_validator.validate_groups.assert_not_called()


if __name__ == '__main__':
    unittest.main()
