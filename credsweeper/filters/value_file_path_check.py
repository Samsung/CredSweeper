from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class ValueFilePathCheck(Filter):
    r"""Check that candidate value is a path or not.

    Check if a value contains either '/' or ':\' separators (but not both)
    and do not have any special characters ( !$`&*()+)
    """

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.value is None:
            return True
        contains_unix_separator = '/' in line_data.value
        contains_windows_separator = ':\\' in line_data.value
        contains_special_characters = any(c in line_data.value for c in " !$`&*()+")
        if (contains_unix_separator ^ contains_windows_separator) and not contains_special_characters:
            return True
        return False
