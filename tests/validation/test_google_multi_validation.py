from typing import List
from unittest.mock import MagicMock, patch

import pytest
from google_auth_oauthlib.flow import InstalledAppFlow
from oauthlib.oauth2 import InvalidGrantError

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials import LineData
from credsweeper.validations import GoogleMultiValidation
from tests.test_utils.dummy_line_data import get_line_data


class TestGoogleMultiValidation:

    @pytest.fixture
    def line_data_list(self) -> List[LineData]:
        line_data_list = []
        line_data = get_line_data()
        line_data.value = "AIzaGiReoGiCrackleCrackle12305670912045"
        line_data_list.append(line_data)
        line_data.value = "AaBbCcDdEeFfGgHhIiJjKkLl"
        line_data_list.append(line_data)
        return line_data_list

    def test_verify_p(self, line_data_list: pytest.fixture) -> None:
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.side_effect = InvalidGrantError('fuzz InvalidGrantError')
            mock.return_value = flow
            validation_result = GoogleMultiValidation.verify(line_data_list)
            assert validation_result == KeyValidationOption.VALIDATED_KEY

    def test_verify_n(self, line_data_list: pytest.fixture) -> None:
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.side_effect = Exception('fuzz flow Exception')
            # InvalidGrantError('fuzz InvalidGrantError')
            mock.return_value = flow
            validation_result = GoogleMultiValidation.verify(line_data_list)
            assert validation_result == KeyValidationOption.INVALID_KEY
