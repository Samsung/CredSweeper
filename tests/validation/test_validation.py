from unittest import mock

import pytest
import regex
from requests import Response

from credsweeper.common.constants import Severity, KeyValidationOption
from credsweeper.credentials import Candidate, LineData
from credsweeper.validations import \
    GithubTokenValidation, \
    GoogleApiKeyValidation, \
    StripeApiKeyValidation, \
    GoogleMultiValidation, \
    SquareClientIdValidation, \
    SquareAccessTokenValidation, \
    SlackTokenValidation, \
    MailChimpKeyValidation
from credsweeper.validations.apply_validation import ApplyValidation


def mocked_requests_get(*args, **kwargs):
    response = Response()
    response.status_code = 200
    response._content = b''
    return response


@mock.patch('requests.get', mock.Mock(side_effect=mocked_requests_get))
@pytest.mark.parametrize("validator", [  #
    GithubTokenValidation,  #
    GoogleApiKeyValidation,  #
    GoogleMultiValidation,  #
    MailChimpKeyValidation,  #
    SlackTokenValidation,  #
    SquareAccessTokenValidation,  #
    SquareClientIdValidation,  #
    StripeApiKeyValidation])
def test_mocked_validation_n(validator):
    candidate = Candidate(
        line_data_list=[  #
            LineData({}, line="dummy line 1", line_num=1, path="dummy path 1", pattern=regex.compile('.*')),
            LineData({}, line="dummy line 2", line_num=2, path="dummy path 2", pattern=regex.compile('.*'))
        ],
        patterns=[regex.compile('.*')], rule_name="Dummy candidate", severity=Severity.INFO, config={},
        validations=[validator])
    candidate.line_data_list[0].value = "-"

    assert candidate.api_validation == KeyValidationOption.NOT_AVAILABLE

    apply_validation = ApplyValidation()
    assert apply_validation.validate(candidate) in [  #
        KeyValidationOption.VALIDATED_KEY,  #
        KeyValidationOption.UNDECIDED,  #
        KeyValidationOption.INVALID_KEY,  #
        KeyValidationOption.NOT_AVAILABLE]
