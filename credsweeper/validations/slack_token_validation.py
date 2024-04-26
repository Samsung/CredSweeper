import logging
from typing import List

import requests

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation

logger = logging.getLogger(__name__)


class SlackTokenValidation(Validation):
    """Validation of Slack Token."""

    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify Slack Token - Authentication token bearing required scopes.

        Based on slack api documentation:
        api.slack.com/methods/auth.test
        api.slack.com/web

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED

        """
        try:
            headers = {"Content-type": "application/json", "Authorization": f"Bearer {line_data_list[0].value}"}
            r = requests.post("https://slack.com/api/auth.test/", headers=headers)
        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
            return KeyValidationOption.UNDECIDED

        try:
            data = r.json()

            if data.get("ok"):
                return KeyValidationOption.VALIDATED_KEY

            error_message = data.get("error")

            if error_message == "invalid_auth":
                return KeyValidationOption.INVALID_KEY

        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")

        return KeyValidationOption.UNDECIDED
