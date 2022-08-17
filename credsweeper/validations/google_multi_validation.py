import logging
from typing import List

from google_auth_oauthlib.flow import InstalledAppFlow
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation

logger = logging.getLogger(__name__)


class GoogleMultiValidation(Validation):
    """Validation of Google Multi token."""

    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        r"""Verify Google Multi token.

        Multi token consisting of value with pattern - 'CLIENT_ID.apps.googleusercontent.com' and 'client_secret'
        with regex 'AIza[0-9A-Za-z\\-_]{35}'

        Based on Google Ad Manager refresh token generator:
        https://github.com/googleads/googleads-python-lib/blob/master/examples/ad_manager/authentication/generate_refresh_token.py

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY

        """
        client_config = {
            "web": {
                "client_id": line_data_list[0].value,
                "client_secret": line_data_list[1].value,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token"
            }
        }

        flow = InstalledAppFlow.from_client_config(client_config, scopes=["https://www.googleapis.com/auth/dfp"])
        try:
            flow.fetch_token(code="0")  # 0 is test value of code.
            # Valid successfully.
            return KeyValidationOption.VALIDATED_KEY
        except InvalidGrantError:
            # Valid if only code was wrong.
            return KeyValidationOption.VALIDATED_KEY
        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
            return KeyValidationOption.INVALID_KEY
