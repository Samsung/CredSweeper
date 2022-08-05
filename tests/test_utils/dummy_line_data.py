import copy
import json
import os

from regex import regex

from credsweeper.common.constants import DEFAULT_ENCODING
from credsweeper.config import Config
from credsweeper.config.default_config import default_config
from credsweeper.credentials import LineData


def config() -> Config:
    config_dict = copy.deepcopy(default_config)
    config_dict["validation"] = {}
    config_dict["validation"]["api_validation"] = False
    config_dict["use_filters"] = True
    config_dict["find_by_ext"] = False
    config_dict["depth"] = 0
    config_dict["size_limit"] = None
    return Config(config_dict)


def get_line_data(file_path: str = "", line: str = "", pattern: str = r".*$", config: Config = config()) -> LineData:
    line_num = 0
    pattern = regex.compile(pattern)
    line_data = LineData(config, line, line_num, file_path, pattern)
    return line_data
