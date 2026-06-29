import logging
import logging.config
from pathlib import Path
from typing import Optional

from credsweeper.app import APP_PATH
from credsweeper.utils.util import Util


class Logger:
    """Class that used to configure logging in CredSweeper."""

    SILENCE = 60

    LEVELS = {
        "NOTSET": logging.NOTSET,
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
        level = Logger.LEVELS.get(log_level.upper())
        if level is None:
            raise ValueError(f"log level given: {log_level} -- must be one of: {' | '.join(Logger.LEVELS.keys())}")
        log_config_path = APP_PATH / "secret" / "log.yaml" if file_path is None else Path(file_path)
        logging_config = Util.yaml_load(log_config_path)
        if logging_config is None:
            raise RuntimeError("Logger init error - check config")
        if "handlers" in logging_config and isinstance(logging_config["handlers"], dict):
            # log directories have to be created before usage
            for handler_name, handler_value in logging_config["handlers"].items():
                if "console" == handler_name:
                    handler_value["level"] = level
                elif "filename" in handler_value:
                    log_dir = Path(handler_value["filename"]).resolve().parent
                    log_dir.mkdir(exist_ok=True, parents=True)
        logging.config.dictConfig(logging_config)
        for module in logging_config.get("ignore", []):
            logging.getLogger(module).setLevel(logging.CRITICAL)
