from dataclasses import dataclass
from functools import cached_property
from typing import List, Optional


@dataclass
class AnalysisTarget:
    """AnalysisTarget"""
    line: str
    line_num: int
    lines: List[str]
    file_path: Optional[str] = None
    file_type: Optional[str] = None
    info: Optional[str] = None

    @cached_property
    def line_len(self) -> int:
        return len(self.line)

    @cached_property
    def lines_len(self) -> int:
        return len(self.lines)
