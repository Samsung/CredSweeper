from dataclasses import dataclass
from typing import List


@dataclass
class AnalysisTarget:
    line: str
    line_num: int
    lines: List[str]
    file_path: str
