from typing import List

import requests

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation


class GithubTokenValidation(Validation):
    """Validation of Github Access Token

    Personal access token validation:
    https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token
    """
    @classmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify Github Access Token

        Based on github REST api documentation:
        https://docs.github.com/en/rest/overview/resources-in-the-rest-api

        Args:
            line_data_list: List of LineData objects, data in current
            credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED
        """
        try:
            r = requests.get(
                "https://api.github.com",
                headers={"Authorization": f"token {line_data_list[0].value}"},
            )
        except requests.exceptions.ConnectionError:
            return KeyValidationOption.UNDECIDED

        # According to documentation, authentication with wrong credentials return 401
        # After detecting several requests with invalid credentials within a short period,
        # the API will temporarily reject all auth attempts with 403
        if r.status_code == 401:
            return KeyValidationOption.INVALID_KEY
        if r.status_code == 200:
            return KeyValidationOption.VALIDATED_KEY
        return KeyValidationOption.UNDECIDED
