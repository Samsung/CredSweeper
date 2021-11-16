from typing import Dict, List

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util


class DiffContentProvider(ContentProvider):
    def __init__(self,
                 file_path: str,
                 change_type: str,
                 diff: List[Dict]) -> None:
        self.change_type = change_type
        self.diff = diff
        self.file_path = file_path

    def get_analysis_target(self) -> List[AnalysisTarget]:
        line_numbs, lines = Util.preprocess_file_diff(self.diff, self.change_type)
        return [AnalysisTarget(line, line_numb, lines, self.file_path) for line_numb, line in zip(line_numbs, lines)]
