from typing import Dict

import pandas as pd

from credsweeper.app import APP_PATH
from credsweeper.utils import Util


def model_config_preprocess(df_all: pd.DataFrame, doc_target: bool) -> Dict[str, float]:
    model_config_path = APP_PATH / "ml_model" / "ml_config.json"
    model_config = Util.json_load(model_config_path)
    ascii_char_set = ''.join(chr(x) for x in range(0x20, 0x7F))
    extra_char_set = "\x1B\t\n\r"  # ESC code, tab and line end variations
    doc_char_set = " ●개공기께내는님당드등로메밀번보복본비사생서석성슈스시암에용워으의이작정주지체큰키토패할호화" if doc_target else ''
    model_config["char_set"] = extra_char_set + ascii_char_set + doc_char_set

    # check whether all extensions from meta are in ml_config.json

    for x in model_config["features"]:
        if "FileExtension" == x["type"]:
            config_extensions = x["kwargs"]["extensions"]
            config_extensions_set = set(config_extensions)
            if len(config_extensions) != len(config_extensions_set):
                print("WARNING: duplicates in config extensions list")
            if any(x != x.lower() for x in config_extensions_set):
                print("WARNING: file extensions in config must be in lowercase")
            break
    else:
        raise RuntimeError(f"FileExtension was not found in config ({model_config_path}) features!")

    data_extension_set = set(df_all["ext"].unique())

    if config_extensions_set != data_extension_set:
        for x in model_config["features"]:
            if "FileExtension" == x["type"]:
                x["kwargs"]["extensions"] = sorted(list(data_extension_set))
                Util.json_dump(model_config, model_config_path)
                break
        # the process must be restarted with updated config
        raise RuntimeError(f"RESTART: differences in extensions:"
                           f"\nconfig:{config_extensions_set.difference(data_extension_set)}"
                           f"\ndata:{data_extension_set.difference(config_extensions_set)}"
                           f"\nFile {model_config_path} was updated.")

    # append all rule names for the feature

    for x in model_config["features"]:
        if "RuleName" == x["type"]:
            config_rules = x["kwargs"]["rule_names"]
            config_rules_set = set(config_rules)
            if len(config_rules) != len(config_rules_set):
                print("WARNING: duplicates in config rule_names list")
            break
    else:
        raise RuntimeError(f"FileExtension was not found in config ({model_config_path}) features!")

    data_rules_set = set(df_all["RuleName"].explode().unique())

    if config_rules_set != data_rules_set:
        for x in model_config["features"]:
            if "RuleName" == x["type"]:
                x["kwargs"]["rule_names"] = sorted(list(data_rules_set))
                Util.json_dump(model_config, model_config_path)
                break
        # the process must be restarted with updated config
        raise RuntimeError(f"RESTART: differences in extensions:"
                           f"\nconfig:{config_rules_set.difference(data_rules_set)}"
                           f"\ndata:{data_rules_set.difference(config_rules_set)}"
                           f"\nFile {model_config_path} was updated.")

    thresholds = model_config["thresholds"]
    assert isinstance(thresholds, dict), thresholds
    print(f"Load thresholds: {thresholds}")
    return thresholds
