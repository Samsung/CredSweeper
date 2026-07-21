import contextlib
import logging
from argparse import BooleanOptionalAction, Namespace, ArgumentParser, ArgumentTypeError
from typing import Any, Union, List

from credsweeper import __version__
from credsweeper.common.constants import ML_HUNK, ThresholdPreset, Severity, RuleType
from credsweeper.logger.logger import Logger

logger = logging.getLogger(__name__)


def positive_int(value: Any) -> int:
    """Check if number of parallel processes is not a positive number."""
    int_value = int(value)
    if int_value <= 0:
        logger.error("Number of parallel processes should be a positive number: %s", value)
        raise ArgumentTypeError(f"{value} should be greater than 0")
    return int_value


def threshold_or_float_or_zero(arg: str) -> Union[int, float, ThresholdPreset]:
    """Return ThresholdPreset or a float from the input string

    Args:
        arg: string that either a float or one of allowed values in ThresholdPreset

    Returns:
        int = 0 to disable ML validator, float if arg convertible to float, ThresholdPreset if one of the allowed values

    Raises:
        ArgumentTypeError: if arg cannot be interpreted as float or ThresholdPreset

    """
    if '0' == arg:
        return 0
    with contextlib.suppress(ValueError):
        value = float(arg)
        if 1 < value:
            logger.warning("Value '%s' sews out all ML candidates", arg)
        return value
    allowed_presents = [e.value for e in ThresholdPreset]
    if arg in allowed_presents:
        return ThresholdPreset[arg]
    raise ArgumentTypeError(f"Value must be int, float or one of {allowed_presents}")


def logger_levels(log_level: str) -> str:
    """Logger level correctness verification and transformation

    Args:
        log_level: string with level

    Returns True if log_level UPPERCASE is one of keys
    """
    val = log_level.upper()
    if val in Logger.LEVELS:
        return val
    raise ArgumentTypeError(f"Log level provided: {log_level} -- must be one of: {' | '.join(Logger.LEVELS.keys())}")


def severity_levels(severity_level: str) -> Severity:
    """Severity level correctness verification and transformation

    Args:
        severity_level: string with level

    Returns Severity matched provided string or throws ArgumentTypeError exception
    """

    if severity := Severity.get(severity_level):
        return severity
    raise ArgumentTypeError(
        f"Severity level provided: {severity_level} -- must be one of: {' | '.join([i.value for i in Severity])}")


def parse_arguments(argv: List[str]) -> Namespace:
    """All CLI arguments are defined here"""
    parser = ArgumentParser(prog="python -m credsweeper")
    single_banner_argument = 1 == len(argv) and "--banner" == argv[0]
    group = parser.add_mutually_exclusive_group(required=not single_banner_argument)
    group.add_argument("--path", nargs="+", help="file or directory to scan", dest="path", metavar="PATH")
    group.add_argument("--diff_path", nargs="+", help="git diff file to scan", dest="diff_path", metavar="PATH")
    group.add_argument("--export_config",
                       nargs="?",
                       help="exporting default config to file (default: config.json)",
                       const="config.json",
                       dest="export_config",
                       metavar="PATH")
    group.add_argument("--export_log_config",
                       nargs="?",
                       help="exporting default logger config to file (default: log.yaml)",
                       const="log.yaml",
                       dest="export_log_config",
                       metavar="PATH")
    group.add_argument("--git", help="git repo to scan", dest="git", metavar="PATH")
    parser.add_argument("--ref",
                        help="scan git repo from the ref, otherwise - all branches were scanned (slow)",
                        dest="ref",
                        type=str)
    parser.add_argument("--rules",
                        help="path of rule config file (default: credsweeper/rules/config.yaml). "
                        f"severity:{[i.value for i in Severity]} "
                        f"type:{[i.value for i in RuleType]}",
                        default=None,
                        dest="rule_path",
                        metavar="PATH")
    parser.add_argument("--severity",
                        help=f"set minimum level for rules to apply {[i.value for i in Severity]}"
                        f"(default: '{Severity.INFO}', case insensitive)",
                        default=Severity.INFO,
                        dest="severity",
                        type=severity_levels)
    parser.add_argument("--config",
                        help="use custom config (default: built-in)",
                        default=None,
                        dest="config_path",
                        metavar="PATH")
    parser.add_argument("--log_config",
                        help="use custom log config (default: built-in)",
                        default=None,
                        dest="log_config_path",
                        metavar="PATH")
    parser.add_argument("--denylist",
                        help="path to a plain text file with lines or secrets to ignore",
                        default=None,
                        dest="denylist_path",
                        metavar="PATH")
    parser.add_argument("--find-by-ext",
                        help="find files by predefined extension",
                        dest="find_by_ext",
                        action="store_true")
    parser.add_argument("--pedantic",
                        help="process files without extension",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--depth",
                        help="additional recursive search in data (experimental)",
                        type=positive_int,
                        dest="depth",
                        default=0,
                        required=False,
                        metavar="POSITIVE_INT")
    parser.add_argument("--no-filters", help="disable filters", dest="no_filters", action="store_false")
    parser.add_argument("--doc", help="document-specific scanning", dest="doc", action="store_true")
    parser.add_argument("--ml_threshold",
                        help="setup threshold for the ml model. "
                        "The lower the threshold - the more credentials will be reported. "
                        f"Allowed values: float between 0 and 1, or any of {[x.value for x in ThresholdPreset]} "
                        "(default: medium)",
                        type=threshold_or_float_or_zero,
                        default=ThresholdPreset.medium,
                        dest="ml_threshold",
                        required=False,
                        metavar="THRESHOLD_OR_FLOAT_OR_ZERO")
    parser.add_argument("--ml_batch_size",
                        "-b",
                        help="batch size for model inference (default: 16)",
                        type=positive_int,
                        dest="ml_batch_size",
                        default=16,
                        required=False,
                        metavar="POSITIVE_INT")
    parser.add_argument("--ml_config",
                        help="use external config for ml model",
                        type=str,
                        default=None,
                        dest="ml_config",
                        required=False,
                        metavar="PATH")
    parser.add_argument("--ml_model",
                        help="use external ml model",
                        type=str,
                        default=None,
                        dest="ml_model",
                        required=False,
                        metavar="PATH")
    parser.add_argument("--ml_providers",
                        help="comma separated list of providers for onnx (CPUExecutionProvider is used by default)",
                        type=str,
                        default=None,
                        dest="ml_providers",
                        required=False,
                        metavar="STR")
    parser.add_argument("--ml_threads_limit",
                        help="set a fixed number of threads for the ML session (default: None)",
                        type=positive_int,
                        dest="ml_threads_limit",
                        default=None,
                        metavar="POSITIVE_INT")
    parser.add_argument("--jobs",
                        "-j",
                        help="number of parallel processes to use (default: 1)",
                        type=positive_int,
                        dest="jobs",
                        default=1,
                        metavar="POSITIVE_INT")
    parser.add_argument("--thrifty",
                        help="clear objects after scan to reduce memory consumption",
                        action=BooleanOptionalAction,
                        default=True)
    parser.add_argument("--skip_ignored",
                        help="parse .gitignore files and skip credentials from ignored objects",
                        dest="skip_ignored",
                        action="store_true")
    parser.add_argument("--error",
                        help="produce error code if credentials are found",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--save-json",
                        nargs="?",
                        help="save result to json file (default: output.json)",
                        const="output.json",
                        dest="json_filename",
                        metavar="PATH")
    parser.add_argument("--save-xlsx",
                        nargs="?",
                        help="save result to xlsx file (default: output.xlsx)",
                        const="output.xlsx",
                        dest="xlsx_filename",
                        metavar="PATH")
    parser.add_argument("--stdout", help="print results to stdout", action=BooleanOptionalAction, default=True)
    parser.add_argument("--color", help="print results with colorization", action=BooleanOptionalAction, default=False)
    parser.add_argument("--hashed",
                        help="line, variable, value will be hashed in output",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--subtext",
                        help=f"line text will be stripped in {2 * ML_HUNK} symbols but value and variable are kept",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--sort",
                        help="enable output sorting",
                        dest="sort_output",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--log",
                        "-l",
                        help=(f"provide logging level of {list(Logger.LEVELS.keys())}"
                              f" (default: 'warning', case insensitive)"),
                        default="warning",
                        dest="log",
                        metavar="LOG_LEVEL",
                        type=logger_levels)
    parser.add_argument("--size_limit",
                        help="set size limit of files that for scanning (eg. 1GB / 10MiB / 1000)",
                        dest="size_limit",
                        default=None)
    parser.add_argument("--banner",
                        help="show version and crc32 sum of CredSweeper files at start",
                        action="store_const",
                        const=True)
    parser.add_argument("--version",
                        "-V",
                        help="show program's version number and exit",
                        action="version",
                        version=f"CredSweeper {__version__}")
    return parser.parse_args(argv)
