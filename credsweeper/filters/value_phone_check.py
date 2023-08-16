import re

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValuePhoneCheck(Filter):
    """Check that value may be a phone number"""

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            False, if the sequence is not card number. True if it is

        """
        if line_data.value is None:
            return True

        if line_data.value.startswith('+'):
            """
            +1 (555) 123-1234
            +81-00-0000-0000
            """
            value = line_data.value
            value.translate("+- )(")
            if 10 <= len(value) <= 15:
                # todo - may be add length check according country plan
                return False
        else:
            """
                 er.set("telephone", "555-555-1212");</code></pre>                 
            """
            if re.compile(r"(?=[^0-9 )(-])[1-9][0-9]{2}-[0-9]{3}-[0-9]{4}").match(line_data.value):
                return False
            if re.compile(r"\([0-9]{2,3}\) ?(-[0-9]{2,4}){1,3}").match(line_data.value):
                return False

        return True
