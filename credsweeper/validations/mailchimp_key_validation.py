import logging
from typing import List

import requests
from requests.auth import HTTPBasicAuth

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation

logger = logging.getLogger(__name__)


class MailChimpKeyValidation(Validation):
    """Validation of MailChimp Key."""

    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify MailChimp Key - Authentication request to the MailChimp Marketing API.

        Based on official API tutorial
        https://mailchimp.com/developer/marketing/guides/quick-start/

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED

        """
        # Sanity check. All MailChimp keys should have "-" character
        if "-" not in line_data_list[0].value:
            return KeyValidationOption.INVALID_KEY

        # Exact server name for the key is saved in the key itself, after "-"
        server = line_data_list[0].value.split("-")[-1]

        try:
            r = requests.get(f"https://{server}.api.mailchimp.com/3.0/ping",
                             auth=HTTPBasicAuth("user", line_data_list[0].value))
        except requests.exceptions.ConnectionError:
            # In case if `server` is not real. requests.get will fail to
            #  connect to the non existing domain
            return KeyValidationOption.INVALID_KEY
        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
            return KeyValidationOption.UNDECIDED

        # Validate if response is 401 Unauthorized. In case of other errors
        #  (like 500) it might be the case that server is down, so we cannot
        #  validate a key with certainty
        if r.status_code == 401:
            return KeyValidationOption.INVALID_KEY
        if r.status_code == 200:
            return KeyValidationOption.VALIDATED_KEY
        return KeyValidationOption.UNDECIDED
