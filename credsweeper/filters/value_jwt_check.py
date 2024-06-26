import contextlib
import json
import string
from typing import Any

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter, ValueEntropyBase64Check
from credsweeper.utils import Util


class ValueJwtCheck(Filter):
    """JWT token check - simple"""
    BASE64_VARIOUS_CHARS = string.ascii_letters + string.digits + "/+-_="
    JWT_KEYS = {
        "alg", "typ", "kid", "k", "n", "id", "key", "role", "exp", "enc", "cty", "cid", "iat", "jti", "password",
        "secret", "token", "arn", "type"
    }

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be A JSON.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """

        if not line_data.value:
            return True
        probability = 0.0
        with contextlib.suppress(Exception):
            jwt_parts = line_data.value.split('.')
            for part in jwt_parts:
                if part.startswith("eyJ"):
                    decoded = Util.decode_base64(part, padding_safe=True, urlsafe_detect=True)
                    if part_data := json.loads(decoded):
                        probability += ValueJwtCheck.check_jwt_recursive(part_data)
                    else:
                        # broken jwt
                        break
                elif part:
                    probability += ValueJwtCheck.check_base64_entropy(part)
            else:
                # all parts passed the test
                if 1.0 > probability:
                    return True
                else:
                    return False
        return True

    @staticmethod
    def check_jwt_recursive(data: Any) -> float:
        """Recursive check for jwt is safe because jwt has no references in data structure"""
        result = 0.0
        if isinstance(data, list):
            for i in data:
                result += ValueJwtCheck.check_jwt_recursive(i)
        elif isinstance(data, dict):
            for k, v in data.items():
                if k in ValueJwtCheck.JWT_KEYS:
                    result += 0.25
                result += ValueJwtCheck.check_jwt_recursive(v)
        elif isinstance(data, str) and 27 <= len(data):
            result = ValueJwtCheck.check_base64_entropy(data)
        else:
            # float, integer, none aren`t analyzed
            pass
        return result

    @staticmethod
    def check_base64_entropy(data: str) -> float:
        """checks whether string has enough entropy"""
        min_entropy = ValueEntropyBase64Check.get_min_data_entropy(len(data))
        entropy = Util.get_shannon_entropy(data, ValueJwtCheck.BASE64_VARIOUS_CHARS)
        if entropy < min_entropy - 1 / len(data):
            result = 0.0
        else:
            result = 0.5 * (entropy / min_entropy)
        return result
