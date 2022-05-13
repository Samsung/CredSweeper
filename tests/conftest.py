import datetime
import json
import os
from argparse import Namespace

import pytest

from credsweeper.common.constants import DEFAULT_ENCODING
from credsweeper.config import Config
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
    return Namespace(path=["tests/samples/password"], ml_validation="true", api_validation="true", json_filename=None)


@pytest.fixture
def config() -> Config:
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(f"{dir_path}/../credsweeper/secret/config.json", "r", encoding=DEFAULT_ENCODING) as conf_file:
        config_dict = json.load(conf_file)

    config_dict["validation"] = {}
    config_dict["validation"]["ml_validation"] = False
    config_dict["validation"]["api_validation"] = False
    config_dict["use_filters"] = True
    config_dict["find_by_ext"] = False
    config_dict["find_by_ext_list"] = [".txt"]
    return Config(config_dict)


@pytest.fixture
def rule(rule_name: str, config: Config, rule_path: str) -> Rule:
    scanner = Scanner(config, rule_path)
    for rule in scanner.rules:
        if rule.rule_name == rule_name:
            return rule
    return


@pytest.fixture
def rule_path() -> str:
    return "credsweeper/rules/config.yaml"


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
