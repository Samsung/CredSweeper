from dataclasses import dataclass
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
