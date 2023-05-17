import pytest

from credsweeper.filters.cred_card_number_check import CreditCardNumberCheck
from tests.filters.conftest import LINE_VALUE_PATTERN
from tests.test_utils.dummy_line_data import get_line_data


class TestCreditCardNumberCheck:

    # https://www.paypalobjects.com/en_AU/vhelp/paypalmanager_help/credit_card_numbers.htm
    @pytest.mark.parametrize(
        "line",
        [
            "0378282246310005",  # American Express
            "5555555555554444",  # MasterCard
            "4111111111111111",  # Visa with correct last digit
        ])
    def test_credit_card_number_check_p(self, file_path: pytest.fixture, line: str) -> None:
        cred_candidate = get_line_data(file_path=file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert CreditCardNumberCheck().run(cred_candidate) is False

    @pytest.mark.parametrize(
        "line",
        [
            "",  # empty line
            "0000000000000000",  # zero variant
            "12345678901234567",  # 17 digits
            "378282246310005",  # American Express in 15 digits
            "abcdefghijklmnop",  # ValueError
            "4111111111111110",  # Visa with wrong last digit
            "4111111111111112",
            "4111111111111113",
            "4111111111111114",
            "4111111111111115",
            "4111111111111116",
            "4111111111111117",
            "4111111111111118",
            "4111111111111119",
        ])
    def test_credit_card_number_check_n(self, file_path: pytest.fixture, line: str) -> None:
        cred_candidate = get_line_data(file_path=file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert CreditCardNumberCheck().run(cred_candidate) is True
