import os
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from typing import Any, Union, Optional

from credsweeper import __version__
from credsweeper.app import CredSweeper
from credsweeper.common.constants import ThresholdPreset
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.patch_provider import PatchProvider
from credsweeper.file_handler.text_provider import TextProvider
from credsweeper.logger.logger import Logger, logging


def positive_int(value: Any) -> int:
    """Check if number of parallel processes is not a positive number."""
    int_value = int(value)
    if int_value <= 0:
        logging.error("Number of parallel processes should be a positive number: %s", value)
        raise ArgumentTypeError(f"{value} should be greater than 0")
    return int_value


def threshold_or_float(arg: str) -> Union[float, ThresholdPreset]:
    """Return ThresholdPreset or a float from the input string

    Args:
        arg: string that either a float or one of allowed values in ThresholdPreset

    Returns:
        float if arg convertible to float, ThresholdPreset if one of the allowed values

    Raises:
        ArgumentTypeError: if arg cannot be interpreted as float or ThresholdPreset

    """
    allowed_presents = [e.value for e in ThresholdPreset]
    try:
        return float(arg)  # try convert to float
    except ValueError:
        pass
    if arg in allowed_presents:
        return ThresholdPreset[arg]
    raise ArgumentTypeError(f"value must be a float or one of {allowed_presents}")


def get_arguments() -> Namespace:
    """All CLI arguments are defined here"""
    parser = ArgumentParser(prog="python -m credsweeper")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--path", nargs="+", help="file or directory to scan", dest="path", metavar="PATH")
    group.add_argument("--diff_path", nargs="+", help="git diff file to scan", dest="diff_path", metavar="PATH")
    parser.add_argument("--rules",
                        nargs="?",
                        help="path of rule config file (default: credsweeper/rules/config.yaml)",
                        default=None,
                        dest="rule_path",
                        metavar="PATH")
    parser.add_argument("--find-by-ext",
                        help="find files by predefined extension.",
                        dest="find_by_ext",
                        action="store_true")
    parser.add_argument("--depth",
                        help="recursive search in files which are zip archives.",
                        type=positive_int,
                        dest="depth",
                        default=0,
                        required=False,
                        metavar="POSITIVE_INT")
    parser.add_argument("--ml_threshold",
                        help="setup threshold for the ml model. "
                        "The lower the threshold - the more credentials will be reported. "
                        f"Allowed values: float between 0 and 1, or any of {[e.value for e in ThresholdPreset]} "
                        "(default: medium)",
                        type=threshold_or_float,
                        default=ThresholdPreset.medium,
                        dest="ml_threshold",
                        required=False,
                        metavar="FLOAT_OR_STR")
    parser.add_argument("-b",
                        "--ml_batch_size",
                        help="batch size for model inference (default: 16)",
                        type=positive_int,
                        dest="ml_batch_size",
                        default=16,
                        required=False,
                        metavar="POSITIVE_INT")
    parser.add_argument("--api_validation",
                        help="add credential api validation option to credsweeper pipeline. "
                        "External API is used to reduce FP for some rule types.",
                        dest="api_validation",
                        action="store_true")
    parser.add_argument("-j",
                        "--jobs",
                        help="number of parallel processes to use (default: 1)",
                        type=positive_int,
                        dest="jobs",
                        default=1,
                        metavar="POSITIVE_INT")
    parser.add_argument("--skip_ignored",
                        help="parse .gitignore files and skip credentials from ignored objects",
                        dest="skip_ignored",
                        action="store_true")
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
    parser.add_argument("-l",
                        "--log",
                        help="provide logging level. Example --log debug, (default: 'warning')",
                        default="warning",
                        dest="log",
                        metavar="LOG_LEVEL",
                        choices=list(Logger.LEVELS))
    parser.add_argument("--size_limit",
                        help="set size limit of files that for scanning (eg. 1GB / 10MiB / 1000)",
                        dest="size_limit",
                        default=None)
    parser.add_argument("--version",
                        "-V",
                        help="show program's version number and exit",
                        action="version",
                        version=f"CredSweeper {__version__}")
    return parser.parse_args()


def get_json_filenames(json_filename: str):
    """Auxiliary function to get names for json files with added and deleted .patch data

    Args:
        json_filename: original json path

    Returns:
        Tuple of paths with added and deleted suffixes

    """
    if json_filename is None:
        return None, None
    added_json_filename = json_filename[:-5] + "_added.json"
    deleted_json_filename = json_filename[:-5] + "_deleted.json"
    return added_json_filename, deleted_json_filename


def scan(args: Namespace, content_provider: FilesProvider, json_filename: Optional[str],
         xlsx_filename: Optional[str]) -> None:
    """Scan content_provider data, print results or save them to json_filename is not None

    Args:
        args: arguments of the application
        content_provider: FilesProvider instance to scan data from
        json_filename: json type report file path or None
        xlsx_filename: xlsx type report file path or None

    Returns:
        None

    """
    credsweeper = CredSweeper(rule_path=args.rule_path,
                              api_validation=args.api_validation,
                              json_filename=json_filename,
                              xlsx_filename=xlsx_filename,
                              pool_count=args.jobs,
                              ml_batch_size=args.ml_batch_size,
                              ml_threshold=args.ml_threshold,
                              find_by_ext=args.find_by_ext,
                              depth=args.depth,
                              size_limit=args.size_limit)
    credsweeper.run(content_provider=content_provider)


def main() -> None:
    """Main function"""
    args = get_arguments()
    os.environ["LOG_LEVEL"] = args.log
    Logger.init_logging(args.log)
    logging.info(f"Init CredSweeper object with arguments: {args}")
    if args.path:
        logging.info(f"Run analyzer on path: {args.path}")
        content_provider: FilesProvider = TextProvider(args.path, skip_ignored=args.skip_ignored)
        scan(args, content_provider, args.json_filename, args.xlsx_filename)
    elif args.diff_path:
        added_json_filename, deleted_json_filename = get_json_filenames(args.json_filename)
        # Analyze added data
        logging.info(f"Run analyzer on added rows from patch files: {args.diff_path}")
        content_provider = PatchProvider(args.diff_path, change_type="added")
        scan(args, content_provider, added_json_filename, args.xlsx_filename)
        # Analyze deleted data
        logging.info(f"Run analyzer on deleted rows from patch files: {args.diff_path}")
        content_provider = PatchProvider(args.diff_path, change_type="deleted")
        scan(args, content_provider, deleted_json_filename, args.xlsx_filename)
    else:
        logging.error("Not specified 'path' or 'diff_path'")


if __name__ == "__main__":
    main()
