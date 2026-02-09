import unittest
from unittest.mock import Mock, patch
import psutil
import gc
import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class MemoryInfo:
    total_mb: float
    available_mb: float
    used_mb: float
    percent_used: float
    process_mb: float

class MemoryMonitor:
    def __init__(self, safety_margin: float = 0.2):
        self.safety_margin = safety_margin
        self.process = psutil.Process()
        
    def get_memory_info(self) -> MemoryInfo:
        memory = psutil.virtual_memory()
        process_memory = self.process.memory_info()
        
        return MemoryInfo(
            total_mb=memory.total / 1024 / 1024,
            available_mb=memory.available / 1024 / 1024,
            used_mb=memory.used / 1024 / 1024,
            percent_used=memory.percent,
            process_mb=process_memory.rss / 1024 / 1024
        )
    
    def get_available_memory_mb(self) -> float:
        memory_info = self.get_memory_info()
        safe_available = memory_info.available_mb * (1 - self.safety_margin)
        return max(0, safe_available - memory_info.process_mb)
    
    def is_memory_pressure_high(self) -> bool:
        memory_info = self.get_memory_info()
        return memory_info.percent_used > (1 - self.safety_margin) * 100
    
    def force_garbage_collection(self) -> float:
        before_mb = self.get_memory_info().process_mb
        gc.collect()
        after_mb = self.get_memory_info().process_mb
        freed_mb = before_mb - after_mb
        if freed_mb > 0:
            logger.debug(f"Garbage collection freed {freed_mb:.2f} MB")
        return freed_mb


class TestMemoryMonitor(unittest.TestCase):

    def setUp(self):
        self.monitor = MemoryMonitor(safety_margin=0.2)

    @patch('psutil.virtual_memory')
    @patch('psutil.Process')
    def test_get_memory_info(self, mock_process, mock_virtual_memory):
        mock_memory = Mock()
        mock_memory.total = 8589934592
        mock_memory.available = 4294967296
        mock_memory.used = 4294967296
        mock_memory.percent = 50.0
        mock_virtual_memory.return_value = mock_memory
        
        mock_proc = Mock()
        mock_proc.memory_info.return_value.rss = 1073741824
        mock_process.return_value = mock_proc
        
        with patch.object(self.monitor, 'process', mock_proc):
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
        mock_memory.total = 8589934592
        mock_memory.available = 4294967296
        mock_memory.used = 4294967296
        mock_memory.percent = 50.0
        mock_virtual_memory.return_value = mock_memory
        
        mock_proc = Mock()
        mock_proc.memory_info.return_value.rss = 1073741824
        mock_process.return_value = mock_proc
        
        with patch.object(self.monitor, 'process', mock_proc):
            available = self.monitor.get_available_memory_mb()
            expected = (4096.0 * 0.8) - 1024.0
            self.assertAlmostEqual(available, expected, places=2)

    @patch('psutil.virtual_memory')
    @patch('psutil.Process')
    def test_is_memory_pressure_high(self, mock_process, mock_virtual_memory):
        mock_memory = Mock()
        mock_memory.total = 8589934592
        mock_memory.available = 4294967296
        mock_memory.used = 4294967296
        mock_memory.percent = 85.0
        mock_virtual_memory.return_value = mock_memory
        
        mock_proc = Mock()
        mock_proc.memory_info.return_value.rss = 1073741824
        mock_process.return_value = mock_proc
        
        with patch.object(self.monitor, 'process', mock_proc):
            self.assertTrue(self.monitor.is_memory_pressure_high())
            
            mock_memory.percent = 75.0
            self.assertFalse(self.monitor.is_memory_pressure_high())

    @patch('gc.collect')
    @patch('psutil.virtual_memory')
    @patch('psutil.Process')
    def test_force_garbage_collection(self, mock_process, mock_virtual_memory, mock_gc_collect):
        mock_gc_collect.return_value = None
        
        mock_memory = Mock()
        mock_memory.total = 8589934592
        mock_memory.available = 4294967296
        mock_memory.used = 4294967296
        mock_memory.percent = 50.0
        mock_virtual_memory.return_value = mock_memory
        
        mock_proc = Mock()
        mock_proc.memory_info.return_value.rss = 1073741824
        mock_process.return_value = mock_proc
        
        with patch.object(self.monitor, 'get_memory_info') as mock_get_info:
            mock_get_info.side_effect = [
                Mock(process_mb=100.0),
                Mock(process_mb=90.0)
            ]
            
            freed = self.monitor.force_garbage_collection()
            
            self.assertEqual(freed, 10.0)
            mock_gc_collect.assert_called_once()


if __name__ == '__main__':
    unittest.main()
