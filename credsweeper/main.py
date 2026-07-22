import binascii
import logging
import os
import sys
import time
from argparse import Namespace
from pathlib import Path
from typing import Dict, Tuple, Sequence, Optional, List

from git import Repo, Commit

from credsweeper import __version__
from credsweeper.app import APP_PATH, CredSweeper
from credsweeper.cli import parse_arguments
from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.patches_provider import PatchesProvider
from credsweeper.logger.logger import Logger
from credsweeper.utils.util import Util

EXIT_SUCCESS = 0
EXIT_FAILURE = 1

logger = logging.getLogger(__name__)


def check_integrity() -> int:
    """Calculates CRC32 of program files

    Returns CRC32 of files in integer
    """
    crc32 = 0
    for root, _dirs, files in os.walk(APP_PATH):
        for file_name in files:
            if Util.get_extension(file_name) in [".py", ".json", ".txt", ".yaml", ".onnx"]:
                file_path = Path(root) / file_name
                if data := Util.read_data(file_path):
                    crc32 ^= binascii.crc32(data)
    return crc32


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
                       ml_threads_limit=args.ml_threads_limit,
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
                    logger.warning("A submodule was not properly initialized or commit was removed: %s", exc)
    return list(result.values())


def drill(args: Namespace) -> Tuple[int, int]:
    """Scan repository for branches and commits

    Args:
        args: arguments of the application

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
        logger.info("Git repository %s with commits: %s", args.git, commits_sha1)
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


def main(argv: Optional[List[str]] = None) -> int:
    """Main function"""
    start_time = time.perf_counter()
    result = EXIT_FAILURE
    credentials_number = 0
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    if args.banner:
        print(f"CredSweeper {__version__} crc32:{check_integrity():08x}")
    Logger.init_logging(args.log, args.log_config_path)
    logger.info("Init CredSweeper object with arguments: %s CWD: %s", args, os.getcwd())
    summary: Dict[str, int] = {}
    if args.path:
        logger.info("Run analyzer on path: %s", args.path)
        content_provider: AbstractProvider = FilesProvider(args.path, skip_ignored=args.skip_ignored)
        credentials_number = scan(args, content_provider)
        summary["Detected Credentials"] = credentials_number
        if 0 <= credentials_number:
            result = EXIT_SUCCESS
    elif args.diff_path:
        # Analyze added data
        logger.info("Run analyzer on added rows from patch files: %s", args.diff_path)
        content_provider = PatchesProvider(args.diff_path, change_type=DiffRowType.ADDED)
        add_credentials_number = scan(args, content_provider)
        summary["Added File Credentials"] = add_credentials_number
        # Analyze deleted data
        logger.info("Run analyzer on deleted rows from patch files: %s", args.diff_path)
        content_provider = PatchesProvider(args.diff_path, change_type=DiffRowType.DELETED)
        del_credentials_number = scan(args, content_provider)
        summary["Deleted File Credentials"] = del_credentials_number
        if 0 <= add_credentials_number and 0 <= del_credentials_number:
            # it means the scan was successful done
            result = EXIT_SUCCESS
            # collect number of all found credential to produce error code when necessary
            credentials_number = add_credentials_number + del_credentials_number
    elif args.git:
        logger.info("Run analyzer on GIT: %s", args.git)
        credentials_number, commits_number = drill(args)
        summary[f"Detected Credentials in {args.git} for {commits_number} commits "] = credentials_number
        if 0 <= credentials_number:
            result = EXIT_SUCCESS
    elif args.export_config:
        logger.info("Exporting default config to file: %s", args.export_config)
        config_dict = Util.json_load(APP_PATH / "secret" / "config.json")
        Util.json_dump(config_dict, args.export_config)
        result = EXIT_SUCCESS
    elif args.export_log_config:
        logger.info("Exporting default logger config to file: %s", args.export_log_config)
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
        print(f"Time Elapsed: {time.perf_counter() - start_time}")

    if args.error and EXIT_SUCCESS == result and 0 < credentials_number:
        # override result when credentials were found with the requirement
        result = EXIT_FAILURE

    return result
