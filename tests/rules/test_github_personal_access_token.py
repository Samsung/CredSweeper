from typing import List

import pytest

from .common import BaseTestRule


class TestGithubPersonalAccessToken(BaseTestRule):
    @pytest.fixture(params=[
        ["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"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Github Personal Access Token"
