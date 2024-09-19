from credsweeper.common.constants import CHUNK_SIZE
from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature
from credsweeper.utils import Util


class HasHtmlTag(Feature):
    """Feature is true if line has HTML tags (HTML file)."""

    def __init__(self) -> None:
        super().__init__()
        self.words = [
            '< img', '<img', '< script', '<script', '< p', '<p', '< link', '<link', '< meta', '<meta', '< a', '<a'
        ]

    def extract(self, candidate: Candidate) -> bool:
        subtext = Util.subtext(candidate.line_data_list[0].line, candidate.line_data_list[0].value_start, CHUNK_SIZE)
        candidate_line_data_list_0_line_lower = subtext.lower()
        if '<' not in candidate_line_data_list_0_line_lower:
            # early check
            return False
        if self.any_word_in_(candidate_line_data_list_0_line_lower):
            return True
        if "/>" in candidate_line_data_list_0_line_lower or "</" in candidate_line_data_list_0_line_lower:
            # possible closed tag
            return True
        return False
