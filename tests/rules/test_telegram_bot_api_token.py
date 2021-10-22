from typing import List

import pytest

from .common import BaseTestRule


class TestTelegramBotApiToken(BaseTestRule):
    @pytest.fixture(params=[["4603348066:AAFMepdNauS475gWKEpuDt9NpytDegUz4-o"], ["3039734276:AAHp--rsrIsieHSGWMPMQ8xAzztmgCp009c"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Telegram Bot API Token"
