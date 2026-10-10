import logging
from logging import DEBUG

TRACE = DEBUG >> 1  # half of DEBUG
SILENCE = max(logging._levelToName.keys()) << 1  # pylint: disable=W0212
