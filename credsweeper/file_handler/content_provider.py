from abc import ABC, abstractmethod
from typing import List, Optional

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.file_handler.analysis_target import AnalysisTarget


class ContentProvider(ABC):
    """Base class to provide access to analysis targets for scanned object."""

    def __init__(self, _file_path: str) -> None:
        self.__file_path = _file_path

    @abstractmethod
    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file diff data to scan.

        Return:
            row objects to analysing

        """
        raise NotImplementedError()

    @property
    def file_path(self) -> str:
        """file_path getter"""
        return self.__file_path

    def lines_to_targets(self, lines: List[str]) -> List[AnalysisTarget]:
        """Creates list of targets with multiline concatenation"""
        targets = []
        previous_target: Optional[AnalysisTarget] = None
        for i, line in enumerate(lines):
            if '\\' == line[-1:]:
                current_line = line[:-1]
                if previous_target:
                    if MAX_LINE_LENGTH >= len(previous_target.line) + len(current_line):
                        # append current string to previous target - no limit reached
                        previous_target.line += current_line
                    else:
                        # let previous target will be not merged with current line
                        targets.append(previous_target)
                        previous_target = AnalysisTarget(current_line, i + 1, lines, self.file_path)
                else:
                    previous_target = AnalysisTarget(current_line, i + 1, lines, self.file_path)
            else:
                if previous_target:
                    if MAX_LINE_LENGTH >= len(previous_target.line) + len(line):
                        previous_target.line += line
                        targets.append(previous_target)
                    else:
                        # use similar code blocks to keep order of target appearing
                        targets.append(previous_target)
                        target = AnalysisTarget(line, i + 1, lines, self.file_path)
                        targets.append(target)
                    previous_target = None
                else:
                    target = AnalysisTarget(line, i + 1, lines, self.file_path)
                    targets.append(target)
        if previous_target:
            targets.append(previous_target)
        return targets
