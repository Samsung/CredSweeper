import contextlib

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class IsSecretNumeric(Feature):
    """Feature is true if candidate value is a numerical value."""

    def extract(self, candidate: Candidate) -> bool:
        with contextlib.suppress(Exception):
            if candidate.line_data_list[0].value.startswith("0x") \
                    and 0xffffffffffffffff >= int(candidate.line_data_list[0].value, 16):
                # value should not exceed 64 bit
                return True
            elif '0' <= candidate.line_data_list[0].value[0] <= '9' \
                    or candidate.line_data_list[0].value[0] in ('.', '-', '+'):
                float(candidate.line_data_list[0].value)
                return True
        return False
