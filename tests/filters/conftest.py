import re

import pytest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor

success_line_list = ["Crackle4421", "passwrd = Crackle4421", "passwrd = 'Crackle4421'"]


@pytest.fixture(params=success_line_list)
def success_line(request) -> str:
    return request.param


LINE_VALUE_PATTERN = re.compile(r"^(?P<value>.*)$")

LINE_VARIABLE_PATTERN = re.compile(r"^(?P<variable>.*)$")

DUMMY_DESCRIPTOR = Descriptor("", "", "")

DUMMY_ANALYSIS_TARGET = AnalysisTarget("", 1, [], DUMMY_DESCRIPTOR)
