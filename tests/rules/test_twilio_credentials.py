from typing import List

import pytest

from credsweeper.file_handler.string_content_provider import StringContentProvider
from .common import BaseTestRule


class TestTwilioCredentials(BaseTestRule):
    """Test cases for Twilio Credentials rule.

    True positives:
    - Prefixed SIDs (AC, SK, MM, SM, etc.) are detected standalone
    - Bare 32-hex tokens are detected with Twilio-context keywords
    """

    @pytest.fixture(params=[
        ["SK4D2F64E2A108CD72F648B1984C3B5A13"],  # SK-prefixed SID
        ["AC4d2f64e2a108cd72f648b1984c3b5a13"],  # AC-prefixed SID
        ["MM1234567890abcdef1234567890abcdef"],  # MM-prefixed SID
        ["SM9876543210fedcba9876543210fedcba"],  # SM-prefixed SID
        ["authToken: '9f8e7d6c5b4a39281706f5e4d3c2b1a0'"],  # bare hex with authToken context
        ["auth_token = \"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\""],  # bare hex with auth_token context
        ["TWILIO_AUTH_TOKEN=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d"],  # bare hex with TWILIO context
    ])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Twilio Credentials"


class TestTwilioCredentialsNegative:
    """Negative test cases: bare 32-hex without Twilio context should NOT match."""

    @pytest.fixture
    def rule_name(self) -> str:
        return "Twilio Credentials"

    @pytest.mark.parametrize("lines", [
        ["hash: d41d8cd98f00b204e9800998ecf8427e"],  # MD5 hash - no twilio context
        ["id: 550e8400e29b41d4a716446655440000"],  # UUID - no twilio context
        ["checksum: 7e79bf807aa611eb9cbdd7bda7eaf1aa"],  # checksum - no twilio context
    ])
    def test_scan_negative(self, file_path: pytest.fixture, lines: List[str],
                           scanner: pytest.fixture) -> None:
        provider = StringContentProvider(lines, file_path=file_path)
        scan_result = scanner.scan(provider)
        assert len(scan_result) == 0, f"False positive detected: {scan_result}"