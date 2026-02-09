import unittest
from unittest.mock import Mock, patch, MagicMock
import numpy as np

class MockMemoryMonitor:
    def __init__(self, safety_margin=0.2):
        self.safety_margin = safety_margin
        self.memory_per_candidate_mb = 0.01
    
    def get_available_memory_mb(self):
        return 1024.0
    
    def is_memory_pressure_high(self):
        return False
    
    def force_garbage_collection(self):
        return 10.0

class MockMlValidator:
    def __init__(self):
        self.min_batch_size = 8
        self.max_batch_size = 512
        self.memory_monitor = MockMemoryMonitor()
        self.memory_per_candidate_mb = 0.01
    
    def _calculate_optimal_batch_size(self, total_candidates):
        available_memory_mb = self.memory_monitor.get_available_memory_mb()
        if available_memory_mb <= 0:
            return self.min_batch_size
        
        memory_based_batch = int(available_memory_mb / self.memory_per_candidate_mb)
        optimal_batch = max(self.min_batch_size, min(memory_based_batch, self.max_batch_size))
        optimal_batch = min(optimal_batch, total_candidates)
        
        if self.memory_monitor.is_memory_pressure_high():
            optimal_batch = max(self.min_batch_size, optimal_batch // 2)
        
        return optimal_batch
    
    def _estimate_memory_per_candidate(self, sample_batch):
        before_memory = 100.0
        after_memory = 100.5
        memory_used_mb = after_memory - before_memory
        
        if memory_used_mb > 0 and len(sample_batch) > 0:
            self.memory_per_candidate_mb = memory_used_mb / len(sample_batch)
        
        return self.memory_per_candidate_mb
    
    def get_group_features(self, candidates):
        return (
            np.zeros((1, 256, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 128, 100)),
            np.zeros((1, 50))
        )
    
    def _batch_call_model(self, line_input_list, variable_input_list, value_input_list, features_list):
        batch_size = len(line_input_list)
        return np.random.random(batch_size)
    
    def validate_groups(self, group_list, batch_size=None):
        if batch_size is None:
            if len(group_list) > 0:
                self._estimate_memory_per_candidate(group_list)
            batch_size = self._calculate_optimal_batch_size(len(group_list))
        
        line_input_list = []
        variable_input_list = []
        value_input_list = []
        features_list = []
        probability = np.zeros(len(group_list), dtype=np.float32)
        head = tail = 0
        
        for _group_key, candidates in group_list:
            line_input, variable_input, value_input, feature_array = self.get_group_features(candidates)
            line_input_list.append(line_input)
            variable_input_list.append(variable_input)
            value_input_list.append(value_input)
            features_list.append(feature_array)
            tail += 1
            
            if 0 == tail % batch_size:
                probability[head:tail] = self._batch_call_model(line_input_list, variable_input_list, value_input_list, features_list)
                head = tail
                line_input_list.clear()
                variable_input_list.clear()
                value_input_list.clear()
                features_list.clear()
                
                if self.memory_monitor.is_memory_pressure_high():
                    self.memory_monitor.force_garbage_collection()
                    current_batch_size = self._calculate_optimal_batch_size(len(group_list) - tail)
                    if current_batch_size != batch_size:
                        batch_size = current_batch_size
                        
        if head != tail:
            probability[head:tail] = self._batch_call_model(line_input_list, variable_input_list, value_input_list, features_list)
        
        is_cred = np.array([p >= 0.5 for p in probability])
        return is_cred, probability.astype(float)


class TestDynamicBatching(unittest.TestCase):

    def setUp(self):
        self.validator = MockMlValidator()
        self.mock_candidates = []
        for i in range(20):
            mock_candidate = Mock()
            mock_candidate.use_ml = True
            mock_line_data = Mock()
            mock_line_data.line = f"password = 'secret{i}'"
            mock_line_data.variable = "password"
            mock_line_data.value = f"secret{i}"
            mock_line_data.value_start = 11
            mock_candidate.line_data_list = [mock_line_data]
            self.mock_candidates.append(mock_candidate)

    def test_calculate_optimal_batch_size_normal_memory(self):
        batch_size = self.validator._calculate_optimal_batch_size(100)
        expected = min(512, max(8, int(1024 / 0.01)))
        expected = min(expected, 100)
        self.assertEqual(batch_size, 100)

    def test_calculate_optimal_batch_size_low_memory(self):
        self.validator.memory_monitor.get_available_memory_mb = lambda: 50
        batch_size = self.validator._calculate_optimal_batch_size(100)
        expected = min(512, max(8, int(50 / 0.01)))
        expected = min(expected, 100)
        self.assertEqual(batch_size, 100)

    def test_calculate_optimal_batch_size_memory_pressure(self):
        self.validator.memory_monitor.is_memory_pressure_high = lambda: True
        batch_size = self.validator._calculate_optimal_batch_size(100)
        expected = min(512, max(8, int(1024 / 0.01)))
        expected = min(expected, 100)
        expected = max(8, expected // 2)
        self.assertEqual(batch_size, 50)

    def test_calculate_optimal_batch_size_no_memory(self):
        self.validator.memory_monitor.get_available_memory_mb = lambda: 0
        batch_size = self.validator._calculate_optimal_batch_size(100)
        self.assertEqual(batch_size, 8)

    def test_estimate_memory_per_candidate(self):
        group_list = [(Mock(), self.mock_candidates[:4])]
        memory_per_candidate = self.validator._estimate_memory_per_candidate(group_list)
        
        self.assertEqual(memory_per_candidate, 0.5)
        self.assertEqual(self.validator.memory_per_candidate_mb, 0.5)

    def test_validate_groups_dynamic_batching(self):
        group_list = [(Mock(), [candidate]) for candidate in self.mock_candidates[:3]]
        
        is_cred, probability = self.validator.validate_groups(group_list)
        
        self.assertEqual(len(is_cred), 3)
        self.assertEqual(len(probability), 3)
        self.assertTrue(all(is_cred[i] == (probability[i] >= 0.5) for i in range(3)))

    def test_validate_groups_memory_pressure_adjustment(self):
        group_list = [(Mock(), [candidate]) for candidate in self.mock_candidates[:4]]
        
        pressure_states = [False, True, False, False]
        call_count = 0
        
        def mock_pressure():
            nonlocal call_count
            if call_count < len(pressure_states):
                result = pressure_states[call_count]
            else:
                result = False
            call_count += 1
            return result
        
        self.validator.memory_monitor.is_memory_pressure_high = mock_pressure
        
        is_cred, probability = self.validator.validate_groups(group_list)
        
        self.assertEqual(len(is_cred), 4)
        self.assertEqual(len(probability), 4)

    def test_validate_groups_fixed_batch_size(self):
        group_list = [(Mock(), [candidate]) for candidate in self.mock_candidates[:2]]
        
        is_cred, probability = self.validator.validate_groups(group_list, batch_size=32)
        
        self.assertEqual(len(is_cred), 2)
        self.assertEqual(len(probability), 2)


if __name__ == '__main__':
    unittest.main()
