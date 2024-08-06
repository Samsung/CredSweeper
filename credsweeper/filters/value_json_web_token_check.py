import contextlib
import json

from credsweeper.common.constants import Chars
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter, ValueEntropyBase64Check
from credsweeper.utils import Util


class ValueJsonWebTokenCheck(Filter):
    """
    Check that candidate is JWT which starts usually from 'eyJ'
    only header is parsed with "typ" or "alg" member from example of RFC7519
    https://datatracker.ietf.org/doc/html/rfc7519
    """
    header_keys = {"alg", "typ", "cty", "enc"}
    payload_keys = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        header_check = False
        payload_check = False
        signature_check = False
        with contextlib.suppress(Exception):
            jwt_parts = line_data.value.split('.')
            for part in jwt_parts:
                data = Util.decode_base64(part, padding_safe=True, urlsafe_detect=True)
                if part.startswith("eyJ"):
                    # open part - just base64 encoded
                    json_keys = json.loads(data).keys()
                    # header will be checked first
                    if not header_check:
                        if header_check := bool(ValueJsonWebTokenCheck.header_keys.intersection(json_keys)):
                            continue
                        else:
                            break
                    # payload follows the header
                    if not payload_check:
                        if payload_check := bool(ValueJsonWebTokenCheck.payload_keys.intersection(json_keys)):
                            continue
                        else:
                            break
                    # any other payloads are allowed
                elif header_check and payload_check and not signature_check:
                    # signature check or skip encrypted part
                    signature_check = not Util.is_ascii_entropy_validate(data)
                else:
                    break
        if header_check and payload_check and signature_check:
            return False
        else:
            return True
