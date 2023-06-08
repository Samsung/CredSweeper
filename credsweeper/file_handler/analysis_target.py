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
    stripped_line: Optional[str] = None
    stripped_line_len: Optional[int] = None
    stripped_lower_line: Optional[str] = None

    def __init__(self,
                 line: str,
                 line_num: int,
                 lines: List[str],
                 file_path: Optional[str] = None,
                 file_type: Optional[str] = None,
                 info: Optional[str] = None,
                 line_len: Optional[int] = None,
                 stripped_line: Optional[str] = None,
                 stripped_line_len: Optional[int] = None,
                 stripped_lower_line: Optional[str] = None,
                 ):
        self.line = line
        self.line_num = line_num
        self.lines = lines
        self.file_path = file_path
        self.file_type = file_type
        self.info = info
        self.line_len = line_len or len(line)
        self.stripped_line = stripped_line or line.strip()
        self.stripped_line_len = stripped_line_len or len(self.stripped_line)
        self.stripped_lower_line = stripped_lower_line or self.stripped_line.lower()
