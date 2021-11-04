import os
from argparse import ArgumentParser, ArgumentTypeError
from typing import Any

from credsweeper.app import CredSweeper
from credsweeper.logger.logger import logging, Logger


def positive_int(value: Any) -> int:
    """Check if number of parallel processes is not a positive number"""
    int_value = int(value)
    if int_value <= 0:
        logging.error("Number of parallel processes should be a positive number: %s", value)
        raise ArgumentTypeError(f"{value} should be greater than 0")
    return int_value


def get_arguments() -> ArgumentParser.parse_args:
    parser = ArgumentParser(prog="python -m credsweeper")
    parser.add_argument("--path",
                        nargs="+",
                        help="file or directory to scan",
                        dest="path",
                        metavar="PATH",
                        required=True)
    parser.add_argument("--rules",
                        nargs="?",
                        help="path of rule config file (default: credsweeper/rules/config.yaml)",
                        default=None,
                        dest="rule_path",
                        metavar="PATH")
    parser.add_argument("--ml_validation", help="ml validation option on", dest="ml_validation", action="store_true")
    parser.add_argument("-b",
                        "--ml_batch_size",
                        help="batch size for model inference (default: 16)",
                        type=positive_int,
                        dest="ml_batch_size",
                        default=16,
                        required=False,
                        metavar="POSITIVE_INT")
    parser.add_argument("--api_validation", help="api validation option on", dest="api_validation", action="store_true")
    parser.add_argument("-j",
                        "--jobs",
                        help="number of parallel processes to use (default: number of CPU cores * 2)",
                        type=positive_int,
                        dest="jobs",
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
    parser.add_argument("-l", 
                        "--log",
                        help="provide logging level. Example --log debug, (default: 'warning')",
                        default="warning",
                        dest="log",
                        metavar="LOG_LEVEL",
                        choices=list(Logger.LEVELS)
                        )
    return parser.parse_args()


def main() -> None:
    args = get_arguments()
    os.environ["LOG_LEVEL"] = args.log
    Logger.init_logging(args.log)
    logging.info(f"Init CredSweeper object with arguments:{args}")
    credsweeper = CredSweeper(rule_path=args.rule_path,
                              ml_validation=args.ml_validation,
                              api_validation=args.api_validation,
                              json_filename=args.json_filename,
                              pool_count=args.jobs,
                              ml_batch_size=args.ml_batch_size)
    logging.info(f"Run analyzer on path :{args.path}")
    credsweeper.run(paths=args.path, skip_ignored=args.skip_ignored)


if __name__ == "__main__":
    main()
