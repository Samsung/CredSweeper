import re
from typing import Optional

from credsweeper.app import APP_PATH
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.utils import Util
from tests.filters.conftest import LINE_VALUE_PATTERN


def config() -> Config:
    config_dict = Util.json_load(APP_PATH / "secret" / "config.json")

    config_dict["validation"] = {}
    config_dict["validation"]["api_validation"] = False
    config_dict["use_filters"] = True
    config_dict["find_by_ext"] = False
    config_dict["depth"] = 0
    config_dict["doc"] = False
    config_dict["size_limit"] = None
    return Config(config_dict)


def get_line_data(test_config: Config = config(),
                  file_path: str = "",
                  line: str = "",
                  pattern: Optional[re.Pattern] = None) -> LineData:
    pattern = re.compile(pattern) if pattern else re.compile(LINE_VALUE_PATTERN)
    line_data = LineData(test_config, line, 0, 1, file_path, Util.get_extension(file_path), "info", pattern)
    return line_data
