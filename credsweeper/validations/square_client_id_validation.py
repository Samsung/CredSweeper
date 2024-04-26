import logging
from typing import List

import requests

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation

logger = logging.getLogger(__name__)


class SquareClientIdValidation(Validation):
    """Validation of Square Client ID."""

    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify Square Client ID.

        The Square issued ID for application, available from the developer dashboard.

        Based on Square OAuth API docs:
        https://developer.squareup.com/reference/square/oauth-api/authorize

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED

        """
        try:
            r = requests.get(f"https://squareup.com/oauth2/authorize?client_id={line_data_list[0].value}",
                             allow_redirects=False)
        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
            return KeyValidationOption.UNDECIDED

        positive_start = "<body>You are being <a"
        positive_end = ">redirected"
        negative = "Unable to find client by that `client_id`"

        # Well authenticated client ID would result in Square trying to redirect
        #  us to the Login page. In the case of not real `client_id` page with
        #  relevant error would be returned
        if positive_start in r.text and positive_end in r.text:
            return KeyValidationOption.VALIDATED_KEY
        if negative in r.text:
            return KeyValidationOption.INVALID_KEY
        return KeyValidationOption.UNDECIDED
