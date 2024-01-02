from typing import List

import pytest

from .common import BaseTestRule


class TestGoogleOAuthKey(BaseTestRule):

    @pytest.fixture(params=[["google_oauth_key = \"ya29.gi_reo_gi_crackle_ln22\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Google OAuth Access Token"
