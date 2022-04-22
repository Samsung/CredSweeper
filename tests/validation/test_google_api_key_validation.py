from typing import List

import pytest

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials import LineData
from credsweeper.validations import GoogleApiKeyValidation
from tests.test_utils.dummy_line_data import get_line_data


@pytest.mark.api_validation
class TestGoogleApiKeyValidation:

    @pytest.fixture
    def line_data_list(self) -> List[LineData]:
        line_data_list = []
        line_data = get_line_data()
        line_data.value = "AIzaGiReoGiCrackleCrackle12305670912045"
        line_data_list.append(line_data)
        return line_data_list

    def test_verify_n(self, line_data_list: pytest.fixture) -> None:
        validation_result = GoogleApiKeyValidation.verify(line_data_list)
        assert validation_result is KeyValidationOption.INVALID_KEY
