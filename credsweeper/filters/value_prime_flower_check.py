import binascii
import contextlib

from reedsolo import RSCodec

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValuePrimeFlowerCheck(Filter):
    """PrimeFlower Token"""

    def __init__(self, config: Config = None) -> None:
        self.rsc = RSCodec(nsym=4, nsize=255, fcr=0, prim=0x11d, generator=2, c_exp=8, single_gen=True)

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        with contextlib.suppress(Exception):
            data = binascii.unhexlify(line_data.value)
            res = self.rsc.decode(data)
            if 16 == len(res[0]):
                return False
        return True
