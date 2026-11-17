from typing import Optional, Tuple, List

from credsweeper.common import static_keyword_checklist
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueDictionaryKeywordCheck(Filter):
    """Check that no word from dictionary present in the candidate value."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.keywords: List[Tuple[str, str, str, int]] = [(x, x.capitalize(), x.upper(), len(x))
                                                          for x in static_keyword_checklist.keyword_list]

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        line_data_value_len = len(line_data.value)
        line_data_value = line_data.value
        for keyword_lower, keyword_capitalize, keyword_upper, keyword_length in self.keywords:
            replaced = False
            if keyword_lower in line_data_value:
                line_data_value = line_data_value.replace(keyword_lower, '\x7F' * keyword_length)
                replaced = True
            if keyword_capitalize in line_data_value:
                line_data_value = line_data_value.replace(keyword_capitalize, '\x7F' * keyword_length)
                replaced = True
            if keyword_upper in line_data_value:
                line_data_value = line_data_value.replace(keyword_upper, '\x7F' * keyword_length)
                replaced = True
            if replaced:
                replaced_len = line_data_value.count('\x7F')
                scrap_len = line_data_value_len - replaced_len
                if scrap_len < 2 * replaced_len:
                    # must be greater than 1/3 of whole value
                    return True
        return False
