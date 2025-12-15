from credsweeper.common.constants import CHUNK_SIZE
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.word_in import WordIn
from credsweeper.utils.util import Util


class HasHtmlTag(WordIn):
    """Feature is true if line has HTML tags (HTML file)."""

    HTML_WORDS = [
        '< img', '<img', '< script', '<script', '< p', '<p', '< link', '<link', '< meta', '<meta', '< a', '<a'
    ]

    def __init__(self) -> None:
        super().__init__(HasHtmlTag.HTML_WORDS)

    def extract(self, candidate: Candidate) -> bool:
        subtext = Util.subtext(candidate.line_data_list[0].line, candidate.line_data_list[0].value_start, CHUNK_SIZE)
        candidate_line_data_list_0_line_lower = subtext.lower()
        if '<' not in candidate_line_data_list_0_line_lower:
            # early check
            return False
        for i in self.words:
            if i in candidate_line_data_list_0_line_lower:
                return True
        if "/>" in candidate_line_data_list_0_line_lower or "</" in candidate_line_data_list_0_line_lower:
            # possible closed tag
            return True
        return False
