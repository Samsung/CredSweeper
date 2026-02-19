import mimetypes
from typing import Dict

import pandas as pd

from credsweeper.app import APP_PATH
from credsweeper.utils.util import Util

ML_CONFIG_PATH = APP_PATH / "ml_model" / "ml_config.json"


def model_config_preprocess(df_all: pd.DataFrame, doc_target: bool) -> Dict[str, float]:
    model_config = Util.json_load(ML_CONFIG_PATH)
    ascii_char_set = ''.join(chr(x) for x in range(0x20, 0x7F))
    extra_char_set = "\x1B\t\n\r"  # ESC code, tab and line end variations
    doc_char_set = " ●가개공기께내는님당드등따로메면문밀방번보복본비사생서석성슈스시암에요용워으의이작정주지채체큰키토팅패필하할호화" if doc_target else ''
    model_config["char_set"] = extra_char_set + ascii_char_set + doc_char_set

    # check whether all extensions from meta are in ml_config.json

    for x in model_config["features"]:
        if "FileExtension" == x["type"]:
            config_extensions = x["kwargs"]["extensions"]
            config_extensions_set = set(config_extensions)
            if len(config_extensions) != len(config_extensions_set):
                print("WARNING: duplicates in config extensions list", flush=True)
            if any(x != x.lower() for x in config_extensions_set):
                print("WARNING: file extensions in config must be in lowercase", flush=True)
            break
    else:
        raise RuntimeError(f"FileExtension was not found in config ({ML_CONFIG_PATH}) features!")

    data_extension_set = set(df_all["ext"].unique())

    if config_extensions_set != data_extension_set:
        unknown_extensions = []
        for x in model_config["features"]:
            if "FileExtension" == x["type"]:
                known_extensions = set(x["kwargs"]["extensions"])
                x["kwargs"]["extensions"] = []
                for extension in sorted(list(data_extension_set)):
                    if extension in known_extensions or mimetypes.guess_type(f"a_file{extension}")[0]:
                        # use already present extensions and well-known additionally
                        x["kwargs"]["extensions"].append(extension)
                    else:
                        # collect all unknown extensions for error log
                        print(f"UNKNOWN EXTENSION: {extension}", flush=True)
                        unknown_extensions.append(extension)
                Util.json_dump(model_config, ML_CONFIG_PATH)
                if known_extensions != set(x["kwargs"]["extensions"]):
                    # the process must be restarted with updated config
                    raise RuntimeError("RESTART: differences in extensions:"
                                       f"\nconfig:{config_extensions_set.difference(data_extension_set)}"
                                       f"\ndata:{data_extension_set.difference(config_extensions_set)}"
                                       f"\nFile {ML_CONFIG_PATH} was updated."
                                       f"\nUnknown extensions:{unknown_extensions if unknown_extensions else None}")
                break

    # append all rule names for the feature

    for x in model_config["features"]:
        if "RuleName" == x["type"]:
            config_rules = x["kwargs"]["rule_names"]
            config_rules_set = set(config_rules)
            if len(config_rules) != len(config_rules_set):
                print("WARNING: duplicates in config rule_names list", flush=True)
            break
    else:
        raise RuntimeError(f"rule_names was not found in config ({ML_CONFIG_PATH}) features!")

    data_rules_set = set(df_all["RuleName"].explode().unique())

    if config_rules_set != data_rules_set:
        sorted_rules = sorted(list(data_rules_set))
        print("Update config rule names with ", sorted_rules, flush=True)
        for x in model_config["features"]:
            if "RuleName" == x["type"]:
                x["kwargs"]["rule_names"] = sorted_rules
                Util.json_dump(model_config, ML_CONFIG_PATH)
                break
        # the process must be restarted with updated config
        raise RuntimeError(f"RESTART: differences in rules:"
                           f"\nconfig:{config_rules_set.difference(data_rules_set)}"
                           f"\ndata:{data_rules_set.difference(config_rules_set)}"
                           f"\nFile {ML_CONFIG_PATH} was updated.")
    else:
        print(config_rules_set, " matches ", data_rules_set, flush=True)

    thresholds = model_config["thresholds"]
    assert isinstance(thresholds, dict), thresholds
    print(f"Load thresholds: {thresholds}", flush=True)
    return thresholds
