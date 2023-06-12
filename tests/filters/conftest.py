import pytest
import regex

from credsweeper.file_handler.analysis_target import AnalysisTarget

success_line_list = ["Crackle4421", "passwd = Crackle4421", "passwd = 'Crackle4421'"]


@pytest.fixture(params=success_line_list)
def success_line(request) -> str:
    return request.param


LINE_VALUE_PATTERN = regex.compile(r"^(?P<value>.*)$")

LINE_VARIABLE_PATTERN = regex.compile(r"^(?P<variable>.*)$")
