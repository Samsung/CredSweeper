import base64
import random
import signal
import statistics
import string
import threading
import time
from datetime import datetime
from multiprocessing import Pool
from typing import Tuple, Dict

from password_strength import PasswordStats

from credsweeper.common.constants import Chars
from credsweeper.filters import ValueEntropyBase36Check
from credsweeper.utils import Util

random_data: str
ITERATIONS = 1000


def pool_initializer() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def evaluate_avg(_args: Tuple[int, float, float]) -> Tuple[float, float]:
    min_avg = _args[1]
    min_dvt = _args[2]
    size = _args[0]
    strengths = []
    for x in range(ITERATIONS):
        offset = x * size
        strength = PasswordStats(random_data[offset:offset + size]).strength()
        strengths.append(strength)
    avg = statistics.mean(strengths)
    dvt = statistics.stdev(strengths, avg)
    if avg < min_avg:
        min_avg = avg
        min_dvt = dvt
    return min_avg, min_dvt


if __name__ == "__main__":

    stats: Dict[int, Tuple[float, float]] = {}
    sizes = [14, 15, 16, 17, 23, 24, 25, 26]
    try:
        for n in range(1000):
            start_time = time.time()
            # rand_bytes = random.randbytes(int(8 * ITERATIONS * max(sizes) / 5))
            # random_data = base64.b32encode(rand_bytes).decode('ascii')
            random_data = ''.join(
                [random.choice(string.digits + string.ascii_lowercase) for _ in range(ITERATIONS * max(sizes))])
            _args = [(i, stats[i][0] if i in stats else 9.9, stats[i][1] if i in stats else 0.0) for i in sizes]
            with Pool(processes=min(16, len(_args)), initializer=pool_initializer) as pool:
                for _size, _res in zip(sizes, pool.map(evaluate_avg, _args)):
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

# 14 = (0.6181187987332276, 0.0238472451623027)
# 15 = (0.6669182877367296, 0.022856165639827154)
# 16 = (0.7096789550301471, 0.01954303656351567)
# 17 = (0.7476931371371266, 0.018475468712591297)
# 23 = (0.8934525243796831, 0.009855519535557949)
# 24 = (0.9081445127802358, 0.008922324438047245)
# 25 = (0.920777784614625, 0.007923779973789742)
# 26 = (0.9316444801923168, 0.007214740010906739)
