from unittest import mock
from unittest.mock import patch, MagicMock

import pytest
import regex
from oauthlib.oauth2 import InvalidGrantError
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


def mocked_requests_post(*args, **kwargs):
    response = Response()
    response.status_code = 200
    response._content = b''
    return response


@mock.patch('requests.get', mock.Mock(side_effect=mocked_requests_get))
@mock.patch('requests.post', mock.Mock(side_effect=mocked_requests_post))
@pytest.mark.parametrize(  #
    "validator",  #
    [  #
        GithubTokenValidation,  #
        GoogleApiKeyValidation,  #
        GoogleMultiValidation,  #
        MailChimpKeyValidation,  #
        SlackTokenValidation,  #
        SquareAccessTokenValidation,  #
        SquareClientIdValidation,  #
        StripeApiKeyValidation  #
    ])
def test_mocked_validation_n(validator):
    candidate = Candidate(
        line_data_list=[  #
            LineData({}, line="dummy line 1", line_num=1, path="dummy path 1", info="", pattern=regex.compile('.*')),
            LineData({}, line="dummy line 2", line_num=2, path="dummy path 2", info="", pattern=regex.compile('.*'))
        ],
        patterns=[regex.compile('.*')],  #
        rule_name="Dummy candidate",  #
        severity=Severity.INFO,  #
        config={},  #
        validations=[validator])
    candidate.line_data_list[0].value = "-"

    assert candidate.api_validation == KeyValidationOption.NOT_AVAILABLE

    apply_validation = ApplyValidation()
    assert apply_validation.validate(candidate) in [  #
        KeyValidationOption.VALIDATED_KEY,  #
        KeyValidationOption.UNDECIDED,  #
        KeyValidationOption.INVALID_KEY,  #
        KeyValidationOption.NOT_AVAILABLE  #
    ]


def test_google_multi_n():
    candidate = Candidate(
        line_data_list=[  #
            LineData({}, line="dummy line 1", line_num=1, path="dummy path 1", info="", pattern=regex.compile('.*')),
            LineData({}, line="dummy line 2", line_num=2, path="dummy path 2", info="", pattern=regex.compile('.*'))
        ],
        patterns=[regex.compile('.*')],  #
        rule_name="Dummy candidate",  #
        severity=Severity.INFO,  #
        config={},  #
        validations=[GoogleMultiValidation])
    with patch("google_auth_oauthlib.flow.InstalledAppFlow.from_client_config") as mock_flow:
        flow = MagicMock()
        flow.fetch_token.side_effect = InvalidGrantError('dummy')
        mock_flow.return_value = flow
        apply_validation = ApplyValidation()
        assert apply_validation.validate(candidate) == KeyValidationOption.VALIDATED_KEY


def mocked_requests_get_403(*args, **kwargs):
    response = Response()
    response.status_code = 403
    response._content = b'{}'
    return response


@mock.patch('requests.get', mock.Mock(side_effect=mocked_requests_get_403))
def test_stripe_validation_n():
    candidate = Candidate(
        line_data_list=[  #
            LineData({}, line="dummy line 1", line_num=1, path="dummy path 1", info="", pattern=regex.compile('.*'))
        ],
        patterns=[regex.compile('.*')],  #
        rule_name="Dummy candidate",  #
        severity=Severity.INFO,  #
        config={},  #
        validations=[StripeApiKeyValidation])
    candidate.line_data_list[0].value = "-"

    assert candidate.api_validation == KeyValidationOption.NOT_AVAILABLE

    apply_validation = ApplyValidation()
    assert KeyValidationOption.UNDECIDED == apply_validation.validate(candidate)
