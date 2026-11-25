import json
import mimetypes
import pathlib
from typing import Dict, Any

import pandas as pd

from credsweeper import MlValidator
from credsweeper.common.constants import UTF_8
from credsweeper.utils.util import Util


def load_model_config(ml_config_path: pathlib.Path) -> dict:
    model_config = Util.json_load(ml_config_path)
    assert isinstance(model_config, dict), type(model_config)
    return model_config


def write_model_config(ml_config_path: pathlib.Path, model_config: Any):
    with open(ml_config_path, 'w', encoding=UTF_8) as f:
        json.dump(model_config, f, indent=4, sort_keys=True, ensure_ascii=True)


def update_charset(doc_target: bool, ml_config_path: pathlib.Path):
    char_set = set(chr(x) for x in range(0x20, 0x7F))
    char_set |= set("\x1B\t\n\r")  # ESC code, tab and line end variations
    if doc_target:
        char_set |= set(" ●가개공기께내는님당드등따로메면문밀방번보복본비사생서석성슈스시암에요용워으의이작정주지채체큰키토팅패필하할호화")
    model_config = load_model_config(ml_config_path)
    model_config["char_set"] = ''.join(sorted(list(char_set)))
    write_model_config(ml_config_path, model_config)


def update_file_extension(ml_config_path: pathlib.Path, df_all: pd.DataFrame, allowed_extensions: list[str]):
    # check whether all extensions from meta are in ml_config.json
    allowed_extensions_set = set(allowed_extensions)
    for extension in allowed_extensions_set:
        assert extension.lower() == extension, f"File extension must be in lowercase"

    data_extension_set = set(df_all["ext"].unique())

    model_config = load_model_config(ml_config_path)

    for feature_config in model_config["features"]:
        if "FileExtension" == feature_config["type"]:
            old_extensions_set = set(feature_config["kwargs"]["extensions"])
            new_config_extensions = []
            for extension in sorted(list(data_extension_set)):
                if extension in allowed_extensions:
                    # use already present extensions
                    new_config_extensions.append(extension)
                elif known_mime_type := mimetypes.guess_type(f"file{extension}")[0]:
                    # well-known additionally
                    print(f"Known MIME {known_mime_type} for {extension}", flush=True)
                    new_config_extensions.append(extension)
                else:
                    # collect all unknown extensions for error log
                    print(f"UNKNOWN EXTENSION: {extension}", flush=True)
            new_extensions_set = set(new_config_extensions)
            if new_extensions_set != old_extensions_set:
                # the process must be restarted with updated config
                feature_config["kwargs"]["extensions"] = new_config_extensions
                write_model_config(ml_config_path, model_config)
                raise RuntimeError("RESTART: differences in extensions:"
                                   f"\nconfig:{old_extensions_set.difference(data_extension_set)}"
                                   f"\ndata:{data_extension_set.difference(old_extensions_set)}"
                                   f"\nFile {ml_config_path} was updated.")
            break
    else:
        raise RuntimeError(f"FileExtension was not found in config {ml_config_path}")


def update_rule_name(ml_config_path: pathlib.Path, df_all: pd.DataFrame):
    # append all rule names for the feature
    model_config = load_model_config(ml_config_path)
    for feature_config in model_config["features"]:
        if "RuleName" == feature_config["type"]:
            config_rules = feature_config["kwargs"]["rule_names"]
            config_rules_set = set(config_rules)
            if len(config_rules) != len(config_rules_set):
                print("WARNING: duplicates in config rule_names list", flush=True)
            break
    else:
        raise RuntimeError(f"rule_names was not found in config ({ml_config_path}) features!")

    data_rules_set = set(df_all["RuleName"].explode().unique())

    if config_rules_set != data_rules_set:
        sorted_rules = sorted(list(data_rules_set))
        print("Update config rule names with ", sorted_rules, flush=True)
        for feature_config in model_config["features"]:
            if "RuleName" == feature_config["type"]:
                feature_config["kwargs"]["rule_names"] = sorted_rules
                write_model_config(ml_config_path, model_config)
                break
        # the process must be restarted with updated config
        raise RuntimeError(f"RESTART: differences in rules:"
                           f"\nconfig:{config_rules_set.difference(data_rules_set)}"
                           f"\ndata:{data_rules_set.difference(config_rules_set)}"
                           f"\nFile {ml_config_path} was updated.")
    else:
        print(config_rules_set, " matches ", data_rules_set, flush=True)


def get_thresholds(ml_config_path: pathlib.Path) -> Dict[str, float]:
    model_config = load_model_config(ml_config_path)
    thresholds = model_config["thresholds"]
    assert isinstance(thresholds, dict), thresholds
    print(f"Load thresholds: {thresholds}", flush=True)
    return thresholds


def model_config_preprocess(
    df_all: pd.DataFrame,
    doc_target: bool,
    ml_config_path: pathlib.Path,
    cred_data_location: str,
) -> Dict[str, float]:
    # use default model for preprocessing
    ml_config_path.write_bytes(MlValidator._default_config.read_bytes())
    allowed_extensions_path = pathlib.Path(cred_data_location) / "allowed_extensions.json"
    allowed_extensions = Util.json_load(allowed_extensions_path)
    assert allowed_extensions, f"Empty allowed extensions list from {allowed_extensions_path}"
    # workaround for CI step
    trial_cnt = 3
    while 0 < trial_cnt:
        trial_cnt -= 1
        # there are 2 times possible fails due ml config might be updated
        try:
            update_charset(doc_target, ml_config_path)
            update_file_extension(ml_config_path, df_all, allowed_extensions)
            update_rule_name(ml_config_path, df_all)
            thresholds = get_thresholds(ml_config_path)
            break
        except RuntimeError as exc:
            if "RESTART:" in str(exc) and 0 <= trial_cnt:
                print(str(exc), flush=True)
                continue
            else:
                raise exc
    else:
        raise RuntimeError("Something went wrong")
    return thresholds
