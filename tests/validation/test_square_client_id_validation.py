from os import environ
from typing import List

import pytest

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials import LineData
from credsweeper.validations import SquareClientIdValidation
from tests.test_utils.dummy_line_data import get_line_data


@pytest.mark.api_validation
class TestSquareClientIdValidation:

    @pytest.fixture
    def line_data_list(self) -> List[LineData]:
        line_data_list = []
        line_data = get_line_data()
        line_data.value = "sq0idp-1235567212325-12355672"
        line_data_list.append(line_data)
        return line_data_list

    @pytest.mark.skipif(environ.get("CIRCLE_PROJECT_USERNAME") is not None,
                        reason="Server blocking requests from CI server")
    def test_verify_n(self, line_data_list: pytest.fixture) -> None:
        validation_result = SquareClientIdValidation.verify(line_data_list)
        assert validation_result is KeyValidationOption.INVALID_KEY
