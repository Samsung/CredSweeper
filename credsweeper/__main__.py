import binascii
import contextlib
import logging
import os
import sys
import time
from argparse import ArgumentParser, ArgumentTypeError, Namespace, BooleanOptionalAction
from pathlib import Path
from typing import Any, Union, Dict, Tuple, Sequence

from git import Repo, Commit

from credsweeper import __version__
from credsweeper.app import APP_PATH, CredSweeper
from credsweeper.common.constants import ThresholdPreset, Severity, RuleType, DiffRowType, ML_HUNK
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.patches_provider import PatchesProvider
from credsweeper.logger.logger import Logger
from credsweeper.utils.util import Util

EXIT_SUCCESS = 0
EXIT_FAILURE = 1

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
    allowed_presents = [e.value for e in ThresholdPreset]
    if '0' == arg:
        return 0
    with contextlib.suppress(ValueError):
        return float(arg)  # try convert to float
    if arg in allowed_presents:
        return ThresholdPreset[arg]
    raise ArgumentTypeError(f"value must be a float or one of {allowed_presents}")


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


def check_integrity() -> int:
    """Calculates CRC32 of program files

    Returns CRC32 of files in integer
    """
    crc32 = 0
    for root, _dirs, files in os.walk(APP_PATH):
        for file_name in files:
            if Util.get_extension(file_name) in [".py", ".json", ".txt", ".yaml", ".onnx"]:
                file_path = Path(root) / file_name
                data = Util.read_data(file_path)
                if data:
                    crc32 ^= binascii.crc32(data)
    return crc32


def get_arguments() -> Namespace:
    """All CLI arguments are defined here"""
    parser = ArgumentParser(prog="python -m credsweeper")
    single_banner_argument = 2 == len(sys.argv) and "--banner" == sys.argv[1]
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
                        f"Allowed values: float between 0 and 1, or any of {[e.value for e in ThresholdPreset]} "
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
    return parser.parse_args()


def get_credsweeper(args: Namespace) -> CredSweeper:
    """Common function to create the instance"""
    if args.denylist_path is not None:
        denylist = [line for line in Util.read_file(args.denylist_path) if line]
    else:
        denylist = []
    return CredSweeper(rule_path=args.rule_path,
                       config_path=args.config_path,
                       json_filename=args.json_filename,
                       xlsx_filename=args.xlsx_filename,
                       stdout=args.stdout,
                       color=args.color,
                       hashed=args.hashed,
                       subtext=args.subtext,
                       sort_output=args.sort_output,
                       use_filters=args.no_filters,
                       pool_count=args.jobs,
                       ml_batch_size=args.ml_batch_size,
                       ml_threshold=args.ml_threshold,
                       ml_config=args.ml_config,
                       ml_model=args.ml_model,
                       ml_providers=args.ml_providers,
                       find_by_ext=args.find_by_ext,
                       pedantic=args.pedantic,
                       depth=args.depth,
                       doc=args.doc,
                       severity=args.severity,
                       size_limit=args.size_limit,
                       exclude_lines=denylist,
                       exclude_values=denylist,
                       thrifty=args.thrifty,
                       log_level=args.log)


def scan(args: Namespace, content_provider: AbstractProvider) -> int:
    """Scan content_provider data, print results or save them to json_filename is not None

    Args:
        args: arguments of the application
        content_provider: FilesProvider instance to scan data from

    Returns:
        Number of detected credentials

    Warnings:
         DeprecationWarning: Using 'json_filename' and/or 'xlsx_filename' will issue a warning.

    """
    try:
        credsweeper = get_credsweeper(args)
        return credsweeper.run(content_provider=content_provider)
    except Exception as exc:
        logger.critical(exc, exc_info=True)
        logger.exception(exc)
    return -1


def get_commit_providers(commit: Commit, repo: Repo) -> Sequence[ByteContentProvider]:
    """Process a commit and for providers"""
    result = {}
    # use the hardcoded sha1 until sha256 objects are not supported by GitPython
    ancestors = commit.parents or [repo.tree("4b825dc642cb6eb9a060e54bf8d69288fbee4904")]
    for parent in ancestors:
        for diff in parent.diff(commit):
            # only result files
            blob_b = diff.b_blob
            if blob_b and blob_b.path not in result:
                try:
                    result[blob_b.path] = ByteContentProvider(content=blob_b.data_stream.read(),
                                                              file_path=str(blob_b.path),
                                                              info=DiffRowType.ADDED.value)
                except Exception as exc:
                    logger.warning(f"A submodule was not properly initialized or commit was removed: {exc}")
    return list(result.values())


def drill(args: Namespace) -> Tuple[int, int]:
    """Scan repository for branches and commits
    Returns:
        total credentials found
        total scanned commits
    """
    total_credentials = 0
    total_commits = 0
    try:
        # repo init first
        repo = Repo(args.git)
        if args.ref:
            commits_sha1 = set(x.commit.hexsha for x in repo.refs if x.name == args.ref)
            if not commits_sha1:
                commits_sha1 = {args.ref}  # single commit sha1 reference
        else:
            commits_sha1 = set(x.commit.hexsha for x in repo.refs
                               if x.name.startswith('origin/') or x.name.startswith('refs/heads/'))
        logger.info(f"Git repository {args.git} with commits: {commits_sha1}")
        # then - credsweeper
        credsweeper = get_credsweeper(args)
        # use flat iterations to avoid recursive limits
        to_scan = set(commits_sha1)
        # local speedup for already scanned commits - avoid file system interactive
        scanned = set()
        # to avoid double-check
        skipped = set()
        while to_scan:
            commit_sha1 = to_scan.pop()
            if commit_sha1 in scanned:
                # the commit was scanned in this launch
                continue
            commit = repo.commit(commit_sha1)
            if commit.parents:
                # add parents only when they were not skipped or scanned previously
                to_scan.update(x.hexsha for x in commit.parents if x.hexsha not in skipped and x.hexsha not in scanned)
            # check whether the commit has been checked and the report is present
            skip_already_scanned = False
            if args.json_filename:
                json_path = Path(args.json_filename)
                json_path = json_path.with_suffix(f".{commit_sha1}{json_path.suffix}")
                if json_path.exists():
                    skip_already_scanned = True
                else:
                    credsweeper.json_filename = json_path
            if args.xlsx_filename:
                xlsx_path = Path(args.xlsx_filename)
                xlsx_path = xlsx_path.with_suffix(f".{commit_sha1}{xlsx_path.suffix}")
                if xlsx_path.exists():
                    skip_already_scanned = True
                else:
                    credsweeper.xlsx_filename = xlsx_path
            if skip_already_scanned:
                skipped.add(commit_sha1)
                logger.info("Skip already scanned commit: %s %s", commit_sha1, commit.committed_datetime.isoformat())
                continue
            logger.info("Scan commit: %s %s", commit_sha1, commit.committed_datetime.isoformat())
            # prepare all files to scan in the commit with bytes->IO transformation to avoid a multiprocess issue
            if providers := get_commit_providers(commit, repo):
                credsweeper.credential_manager.candidates.clear()
                credsweeper.scan(providers)
                credsweeper.post_processing()
                credsweeper.export_results()
                total_credentials += credsweeper.credential_manager.len_credentials()
            total_commits += 1
            scanned.add(commit_sha1)
    except Exception as exc:
        logger.critical(exc, exc_info=True)
        return -1, total_commits
    return total_credentials, total_commits


def main() -> int:
    """Main function"""
    result = EXIT_FAILURE
    credentials_number = 0
    start_time = time.time()
    args = get_arguments()
    if args.banner:
        print(f"CredSweeper {__version__} crc32:{check_integrity():08x}")
    Logger.init_logging(args.log, args.log_config_path)
    logger.info(f"Init CredSweeper object with arguments: {args} CWD: {os.getcwd()}")
    summary: Dict[str, int] = {}
    if args.path:
        logger.info(f"Run analyzer on path: {args.path}")
        content_provider: AbstractProvider = FilesProvider(args.path, skip_ignored=args.skip_ignored)
        credentials_number = scan(args, content_provider)
        summary["Detected Credentials"] = credentials_number
        if 0 <= credentials_number:
            result = EXIT_SUCCESS
    elif args.diff_path:
        # Analyze added data
        logger.info(f"Run analyzer on added rows from patch files: {args.diff_path}")
        content_provider = PatchesProvider(args.diff_path, change_type=DiffRowType.ADDED)
        add_credentials_number = scan(args, content_provider)
        summary["Added File Credentials"] = add_credentials_number
        # Analyze deleted data
        logger.info(f"Run analyzer on deleted rows from patch files: {args.diff_path}")
        content_provider = PatchesProvider(args.diff_path, change_type=DiffRowType.DELETED)
        del_credentials_number = scan(args, content_provider)
        summary["Deleted File Credentials"] = del_credentials_number
        if 0 <= add_credentials_number and 0 <= del_credentials_number:
            # it means the scan was successful done
            result = EXIT_SUCCESS
            # collect number of all found credential to produce error code when necessary
            credentials_number = add_credentials_number + del_credentials_number
    elif args.git:
        logger.info(f"Run analyzer on GIT: {args.git}")
        credentials_number, commits_number = drill(args)
        summary[f"Detected Credentials in {args.git} for {commits_number} commits "] = credentials_number
        if 0 <= credentials_number:
            result = EXIT_SUCCESS
    elif args.export_config:
        logging.info(f"Exporting default config to file: {args.export_config}")
        config_dict = Util.json_load(APP_PATH / "secret" / "config.json")
        Util.json_dump(config_dict, args.export_config)
        result = EXIT_SUCCESS
    elif args.export_log_config:
        logging.info(f"Exporting default logger config to file: {args.export_log_config}")
        config_dict = Util.yaml_load(APP_PATH / "secret" / "log.yaml")
        Util.yaml_dump(config_dict, args.export_log_config)
        result = EXIT_SUCCESS
    elif args.banner and 2 == len(sys.argv):
        # only extend version invocation
        result = EXIT_SUCCESS
    else:
        logger.error("Not specified 'path' or 'diff_path'")

    if EXIT_SUCCESS == result and len(summary):
        for k, v in summary.items():
            print(f"{k}: {v}")
        end_time = time.time()
        print(f"Time Elapsed: {end_time - start_time}s")

    if args.error and EXIT_SUCCESS == result and 0 < credentials_number:
        # override result when credentials were found with the requirement
        result = EXIT_FAILURE

    return result


if __name__ == "__main__":
    sys.exit(main())
