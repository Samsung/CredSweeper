from typing import List


class AnalysisTarget:
    def __init__(self, line: str, line_num: int, lines: List[str], file_path: str):
        self.line = line
        self.line_num = line_num
        self.lines = lines
        self.file_path = file_path
