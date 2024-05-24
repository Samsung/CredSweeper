import logging
from typing import List

import requests

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation

logger = logging.getLogger(__name__)


class GoogleApiKeyValidation(Validation):
    """Validation of Google API Key."""

    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify Google API Key of Google Maps Platform products.

        Based on Google Map Place Search API:
        https://developers.google.com/places/web-service/search

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED

        """
        try:
            # Note that requests without "input" and "inputtype" URL arguments
            #  requests is invalid and will always be denied. But Google will still
            #  validate the "key", so we will know if it's real or not.
            r = requests.get(
                f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?key={line_data_list[0].value}")
        except Exception as exc:
            logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")
            return KeyValidationOption.UNDECIDED

        # Google sends 200 even in case of REQUEST_DENIED
        if r.status_code == 200:
            try:
                data = r.json()
                status = data.get("status")

                if status != "REQUEST_DENIED":
                    # VALIDATED if request is not denied
                    return KeyValidationOption.VALIDATED_KEY
                else:
                    error_message = data.get("error_message")
                    # VALIDATED key is legit, but not authorized for Maps API
                    if error_message == "This API project is not authorized to use this API.":
                        return KeyValidationOption.VALIDATED_KEY
                    # Invalid if Google explicitly say so
                    if error_message == "The provided API key is invalid.":
                        return KeyValidationOption.INVALID_KEY

            except Exception as exc:
                logger.error(f"Cannot validate {line_data_list[0].value} token using API\n{exc}")

        # Undecided otherwise
        return KeyValidationOption.UNDECIDED
