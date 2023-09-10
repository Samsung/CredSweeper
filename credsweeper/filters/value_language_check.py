import contextualSpellCheck
import spacy

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueLanguageCheck(Filter):
    """

    """

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Return: True, when need to filter candidate and False if left"""
        if not line_data.value:
            return True
        nlp = spacy.load('en_core_web_sm')
        contextualSpellCheck.add_to_pipe(nlp)
        doc = nlp(line_data.value)
        check = doc._.suggestions_spellCheck
        if check:
            return False

        return True
