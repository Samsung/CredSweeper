import unittest
from unittest.mock import Mock, patch
import numpy as np
import psutil

from credsweeper.ml_model.memory_monitor import MemoryMonitor, MemoryInfo


class TestMemoryMonitor(unittest.TestCase):

    def setUp(self):
        self.monitor = MemoryMonitor(safety_margin=0.2)

    @patch('psutil.virtual_memory')
    @patch('psutil.Process')
    def test_get_memory_info(self, mock_process, mock_virtual_memory):
        mock_memory = Mock()
        mock_memory.total = 8589934592  # 8GB
        mock_memory.available = 4294967296  # 4GB
        mock_memory.used = 4294967296  # 4GB
        mock_memory.percent = 50.0
        mock_virtual_memory.return_value = mock_memory
        
        mock_proc = Mock()
        mock_proc.memory_info.return_value.rss = 1073741824  # 1GB
        mock_process.return_value = mock_proc
        
        info = self.monitor.get_memory_info()
        
        self.assertEqual(info.total_mb, 8192.0)
        self.assertEqual(info.available_mb, 4096.0)
        self.assertEqual(info.used_mb, 4096.0)
        self.assertEqual(info.percent_used, 50.0)
        self.assertEqual(info.process_mb, 1024.0)

    @patch('psutil.virtual_memory')
    @patch('psutil.Process')
    def test_get_available_memory_mb(self, mock_process, mock_virtual_memory):
        mock_memory = Mock()
        mock_memory.available = 4294967296  # 4GB
        mock_virtual_memory.return_value = mock_memory
        
        mock_proc = Mock()
        mock_proc.memory_info.return_value.rss = 1073741824  # 1GB
        mock_process.return_value = mock_proc
        
        available = self.monitor.get_available_memory_mb()
        expected = (4096.0 * 0.8) - 1024.0  # 3276.8 - 1024 = 2252.8
        self.assertAlmostEqual(available, expected, places=2)

    @patch('psutil.virtual_memory')
    def test_is_memory_pressure_high(self, mock_virtual_memory):
        mock_memory = Mock()
        mock_memory.percent = 85.0
        mock_virtual_memory.return_value = mock_memory
        
        self.assertTrue(self.monitor.is_memory_pressure_high())
        
        mock_memory.percent = 75.0
        self.assertFalse(self.monitor.is_memory_pressure_high())

    @patch('gc.collect')
    @patch.object(MemoryMonitor, 'get_memory_info')
    def test_force_garbage_collection(self, mock_get_memory_info, mock_gc_collect):
        mock_gc_collect.return_value = None
        
        mock_before = MemoryInfo(8192, 4096, 4096, 50, 1024)
        mock_after = MemoryInfo(8192, 4096, 4096, 50, 512)
        mock_get_memory_info.side_effect = [mock_before, mock_after]
        
        freed = self.monitor.force_garbage_collection()
        
        self.assertEqual(freed, 512.0)
        mock_gc_collect.assert_called_once()


if __name__ == '__main__':
    unittest.main()
