import logging
import logging.config
from pathlib import Path
from typing import Optional

from credsweeper.app import APP_PATH
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
    def init_logging(log_level: str, file_path: Optional[str] = None) -> None:
        """Init logger.

        Init logging with configuration from file 'credsweeper_path/secret/log.yaml'. For configure log level of
            console output used 'log_level' args

        Args:
            log_level: log level for console output
            file_path: path of custom log config

        """
        try:
            level = Logger.LEVELS.get(log_level.upper())
            if level is None:
                raise ValueError(f"log level given: {log_level} -- must be one of: {' | '.join(Logger.LEVELS.keys())}")
            logging_config = Util.yaml_load(file_path) if file_path else None
            if not logging_config:
                logging_config = Util.yaml_load(APP_PATH / "secret" / "log.yaml")
            log_dir = Path(logging_config["handlers"]["logfile"]["filename"]).resolve().parent
            log_dir.mkdir(exist_ok=True)
            logging_config["handlers"]["console"]["level"] = level
            logging.config.dictConfig(logging_config)
            for module in logging_config["ignore"]:
                logging.getLogger(module).setLevel(logging.ERROR)
        except OSError:
            logging.basicConfig(level=logging.WARNING)
