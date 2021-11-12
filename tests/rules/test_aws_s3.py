from typing import List

import pytest

from .common import BaseTestRule


class TestAwsS3(BaseTestRule):
    @pytest.fixture(params=[
        ["storage.lol.com.s3.amazonaws.com"],
        ["storage.lol.com.s3-website.ap-south-1.amazonaws.com"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "AWS S3 Bucket"
