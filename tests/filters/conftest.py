import re

import pytest

from credsweeper.common.keyword_pattern import KeywordPattern
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.scanner.scanner import RULES_PATH
from credsweeper.utils.util import Util

success_line_list = [  #
    "\"passwd\": \"Crackle4421\"",  #
    "passwd = Crackle4421",  #
    "passwd = 'Crackle4421'",  #
    "passwd='''MyP@5$word''';",  #
    'passwd="""MyP@5$word""";',  #
    "passwd = 'Crackle4421'",  #
    "export passwd=Crackle4421;",  #
    "// passwd = Crackle4421",  #
    "/* passwd = Crackle4421",  #
    " * passwd = Crackle4421",  #
    "# passwd = Crackle4421",  #
]


@pytest.fixture(params=success_line_list)
def success_line(request) -> str:
    return request.param


KEYWORD_PASSWORD_PATTERN = KeywordPattern.get_keyword_pattern(
    list(x["values"][0] for x in Util.yaml_load(RULES_PATH) if "Password" == x["name"])[0])

LINE_VALUE_PATTERN = re.compile(r"^(?P<value>.*)$")

LINE_VARIABLE_PATTERN = re.compile(r"^(?P<variable>.*)$")

DUMMY_DESCRIPTOR = Descriptor("", "", "")

DUMMY_ANALYSIS_TARGET = AnalysisTarget(line_pos=0, lines=[""], line_nums=[1], descriptor=DUMMY_DESCRIPTOR)
