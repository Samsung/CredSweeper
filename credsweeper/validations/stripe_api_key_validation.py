import logging
import re
from typing import List

import requests

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation

logger = logging.getLogger(__name__)


class StripeApiKeyValidation(Validation):
    """Stripe API Key validation."""

    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify Stripe API Key - API keys uses to authenticate requests.

        Based on Stripe Authentication documentation:
        https://stripe.com/docs/api/authentication

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED

        """
        try:
            r = requests.get("https://api.stripe.com/v1/charges", auth=(line_data_list[0].value, ""))
        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
            return KeyValidationOption.UNDECIDED
        # According to documentation, authentication with wrong credentials return 401
        # If key provided is of restricted type, valid but doesn't have right permission,
        # then 403 will be returned and a message with description
        if r.status_code == 401:
            return KeyValidationOption.INVALID_KEY
        if r.status_code == 200:
            return KeyValidationOption.VALIDATED_KEY
        if r.status_code == 403:
            begin = "The provided key 'rk_"
            end = "Having the 'rak_charge_read' permission would allow this request to continue."
            try:
                if re.search(begin + ".*" + end + "$", r.json()["error"]["message"]):
                    return KeyValidationOption.VALIDATED_KEY
            except Exception as exc:
                logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
        return KeyValidationOption.UNDECIDED
