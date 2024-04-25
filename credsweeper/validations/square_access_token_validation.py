import logging
from typing import List

import requests

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation

logger = logging.getLogger(__name__)


class SquareAccessTokenValidation(Validation):
    """Validation of Square Access Token."""

    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify Square Access Token.

        Square Access Token - Scoped access token, Grants seller-scoped and
        limited access to a Square account by asking an authenticated user
        for explicit permissions.

        Based on Square API docs:
        https://developer.squareup.com/docs/get-started
        Note that if you want to test it yourself you need to select
        Production API key, not the Sandbox one

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED

        """
        try:
            r = requests.post(
                "https://connect.squareup.com/v2/payments",
                headers={"Authorization": f"Bearer {line_data_list[0].value}"},
            )
        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
            return KeyValidationOption.UNDECIDED

        # We actually expect successfully authenticated request to fail with 400
        #  (Bad Request) as we provided no body for the POST. If authentication
        #  failed we will see 401, not 400
        if r.status_code in [200, 400]:
            return KeyValidationOption.VALIDATED_KEY
        if r.status_code == 401:
            return KeyValidationOption.INVALID_KEY
        return KeyValidationOption.UNDECIDED
