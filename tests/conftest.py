import copy
import datetime
import json
import os
from argparse import Namespace
from typing import Optional

import pytest

from credsweeper.common.constants import DEFAULT_ENCODING
from credsweeper.config import Config
from credsweeper.config.default_config import default_config
from credsweeper.rules import Rule
from credsweeper.scanner import Scanner


@pytest.fixture
def python_file_path() -> str:
    return f"test_file_{str(datetime.datetime.now())}.py"


@pytest.fixture
def file_path() -> str:
    return f"test_file_{str(datetime.datetime.now())}"


@pytest.fixture
def args() -> Namespace:
    return Namespace(path=["tests/samples/password"], api_validation="true", json_filename=None)


@pytest.fixture
def config() -> Config:
    config_dict = copy.deepcopy(default_config)
    config_dict["validation"] = {}
    config_dict["validation"]["api_validation"] = False
    config_dict["use_filters"] = True
    config_dict["find_by_ext"] = False
    config_dict["depth"] = 0
    config_dict["find_by_ext_list"] = [".txt"]
    config_dict["size_limit"] = None
    return Config(config_dict)


@pytest.fixture
def rule(rule_name: str, config: Config, rule_path: str) -> Optional[Rule]:
    scanner = Scanner(config, rule_path)
    for rule in scanner.rules:
        if rule.rule_name == rule_name:
            return rule
    return None


@pytest.fixture
def rule_path() -> Optional[str]:
    return None


@pytest.fixture
def scanner(rule: Rule, config: Config, rule_path: str) -> Scanner:
    scanner = Scanner(config, rule_path)
    scanner.rules = [rule]
    return scanner


@pytest.fixture
def scanner_without_filters(rule: Rule, config: Config, rule_path: str):
    config.use_filters = False
    scanner = Scanner(config, rule_path)
    scanner.rules = [rule]
    return scanner
