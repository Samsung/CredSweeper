import contextualSpellCheck
import spacy

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueLanguageCheck(Filter):
    """
    Use NLP lib to filter out regular words
    """

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Return: True, when need to filter candidate and False if left"""
        if not line_data.value:
            return True
        nlp = spacy.load('en_core_web_sm')
        contextualSpellCheck.add_to_pipe(nlp)
        value = line_data.value
        sanitized_val_len = 0
        while value and sanitized_val_len != len(value):
            sanitized_val_len = len(value)
            # Remove extra \s
            value = value.strip()
            # Remove trailing `'"`
            value = value.rstrip('.')
            value = value.rstrip(",")
            value = value.rstrip(")")

        doc = nlp(value)
        check = doc._.suggestions_spellCheck
        if check:
            return False

        return True
