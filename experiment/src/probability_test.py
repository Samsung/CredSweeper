import base64
import random
import signal
import threading
import time
from datetime import datetime
from multiprocessing import Pool
from typing import Tuple, Dict, List

from credsweeper.common.constants import Chars
from credsweeper.filters import ValueEntropyBase36Check
from credsweeper.utils import Util

random_data: str
ITERATIONS = 100000


def pool_initializer() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def evaluate_maxcnt(_args: Tuple[int, List[int]]) -> List[int]:
    size = _args[0]
    max_list = _args[1]
    max_cnt = max_list[0]
    for x in range(ITERATIONS):
        cnt_list = []
        offset = x * size
        data = random_data[offset:offset + size]

        for i in str(Chars.BASE64STD_CHARS.value):
            cnt = data.count(i)
            if cnt:
                cnt_list.append(cnt)
        cnt_list.sort(reverse=True)
        if cnt_list[0] > max_cnt:
            max_list = cnt_list
    return max_list


if __name__ == "__main__":

    stats: Dict[int, List[int]] = {}
    sizes = [16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 31, 32, 33, 63, 64]
    try:
        for n in range(1000):
            start_time = time.time()
            rand_bytes = random.randbytes(int(3 * ITERATIONS * max(sizes) / 4))
            random_data = base64.standard_b64encode(rand_bytes).decode('ascii')
            _args = [(i, stats[i] if i in stats else [0]) for i in sizes]
            with Pool(processes=min(16, len(_args)), initializer=pool_initializer) as pool:
                for _size, _res in zip(sizes, pool.map(evaluate_maxcnt, _args)):
                    with threading.Lock():
                        stats[_size] = _res
            print(f"done {n} in {time.time() - start_time}", flush=True)
            for k, v in stats.items():
                print(f"{k} = {v}", flush=True)
    except KeyboardInterrupt as exc:
        print(exc)
    finally:
        print("===========================================================")
    for k, v in stats.items():
        print(f"{k} = {v}", flush=True)

# done 157 in 2.0856435298919678
# 16 = [7, 2, 1, 1, 1, 1, 1, 1, 1]
# 17 = [7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 18 = [7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 19 = [7, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 20 = [8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 21 = [7, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 22 = [8, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1]
# 24 = [8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 25 = [8, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 26 = [8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 31 = [8, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 32 = [8, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 33 = [9, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 63 = [12, 4, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
# 64 = [12, 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
