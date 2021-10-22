import logging
from pathlib import Path

import yaml


CONFIG_PATH = Path(__file__).resolve().parent.parent.joinpath('secret')

class ConfigManager:
    @staticmethod
    def load_conf(conf_file):
        file_path = CONFIG_PATH.joinpath(conf_file)
        try:
            with open(file_path, 'r') as f:
                conf = yaml.load(f, Loader=yaml.FullLoader)
        except (IOError, OSError):
            logging.error(f"Failed to read {file_path}")
            raise

        return conf
