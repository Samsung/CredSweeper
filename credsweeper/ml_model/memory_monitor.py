import gc
import logging
import psutil
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
