import logging
import logging.config
import os
from pathlib import Path

from credsweeper.config import ConfigManager

SILENCE = 60


class Logger:
    """Class that used to configure logging in CredSweeper."""

    LEVELS = {
        "critical": logging.CRITICAL,
        "error": logging.ERROR,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
        "silence": SILENCE
    }

    @staticmethod
    def init_logging(log_level: str) -> None:
        """Init logger.

        Init logging with configuration from file 'credsweeper_path/secret/log.yaml'. For configure log level of
            console output used 'log_level' args

        Args:
            log_level: log level for console output

        """
        try:
            level = Logger.LEVELS.get(log_level.lower())
            if level is None:
                raise ValueError(f"log level given: {log_level} -- must be one of: {' | '.join(Logger.LEVELS.keys())}")
            logging_config = ConfigManager.load_conf("log.yaml")
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


log_level = os.getenv("LOG_LEVEL")
if log_level is None:
    log_level = "warning"

Logger.init_logging(log_level)
