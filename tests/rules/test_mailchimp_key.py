from typing import List

import pytest

from .common import BaseTestRule


class TestMailChimpKey(BaseTestRule):

    @pytest.fixture(params=[["mailchimp_key = \"abcaefaacdaf01214561891121451781-us12\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "MailChimp API Key"
