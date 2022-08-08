import copy
import logging
import logging.config

from pathlib import Path

from credsweeper.logger.log_config import default_log_config
from credsweeper.utils import Util


class Logger:
    """Class that used to configure logging in CredSweeper."""

    SILENCE = 60

    LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "FATAL": logging.CRITICAL,
        "CRITICAL": logging.CRITICAL,
        "SILENCE": SILENCE
    }

    @staticmethod
    def init_logging(log_level: str, log_config_file: str = None) -> None:
        """Init logger.

        Init logging with configuration from file 'credsweeper_path/secret/log.json'. For configure log level of
            console output used 'log_level' args

        Args:
            log_level: log level for console output
            log_config_file: custom config for logging

        """
        try:
            level = Logger.LEVELS.get(log_level.upper())
            if level is None:
                raise ValueError(f"log level given: {log_level} -- must be one of: {' | '.join(Logger.LEVELS.keys())}")

            custom_config = Util.json_read(log_config_file) if log_config_file else None
            logging_config = custom_config if custom_config else copy.deepcopy(default_log_config)
            file_path = Path(__file__).resolve().parent.parent
            log_path = file_path.joinpath(logging_config["handlers"]["logfile"]["filename"])
            log_path.parent.mkdir(exist_ok=True)
            logging_config["handlers"]["console"]["level"] = level
            logging_config["handlers"]["logfile"]["filename"] = log_path
            logging_config["handlers"]["error_log"]["filename"] = \
                file_path.joinpath(logging_config["handlers"]["error_log"]["filename"])
            logging.config.dictConfig(logging_config)
            for module in logging_config["ignore"]:
                logging.getLogger(module).setLevel(logging.ERROR)
        except (IOError, OSError):
            logging.basicConfig(level=logging.WARNING)
