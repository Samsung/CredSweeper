from typing import List
from unittest.mock import patch

import pytest
import requests
from requests import Response

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials import LineData
from credsweeper.validations import StripeApiKeyValidation
from tests.test_utils.dummy_line_data import get_line_data


@pytest.mark.api_validation
class TestStripeApiKeyValidation:

    @pytest.fixture
    def line_data_list(self) -> List[LineData]:
        line_data_list = []
        line_data = get_line_data()
        line_data.value = "sk_live_abcfefgyijkgmnoqqrsjuvwtyz0128456989ABCFEFGAI" \
                          "JDLANOPRRSTHVWQYZ0128456989abcfefgyijkgmnoqqrsjuvwtyz0"
        line_data_list.append(line_data)
        return line_data_list

    def test_verify_p(self, line_data_list: pytest.fixture) -> None:
        response = Response()
        response.status_code = 200
        with patch(requests.__name__ + "." + requests.get.__name__, return_value=response):
            validation_result = StripeApiKeyValidation.verify(line_data_list)
        assert validation_result is KeyValidationOption.VALIDATED_KEY

    def test_verify_n(self, line_data_list: pytest.fixture) -> None:
        response = Response()
        response.status_code = 401
        with patch(requests.__name__ + "." + requests.get.__name__, return_value=response):
            validation_result = StripeApiKeyValidation.verify(line_data_list)
        assert validation_result is KeyValidationOption.INVALID_KEY
