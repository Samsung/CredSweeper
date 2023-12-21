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
            rand_bytes = random.randbytes(int(8 * ITERATIONS * max(sizes) / 5))
            random_data = base64.b32encode(rand_bytes).decode('ascii')
            # random_data = ''.join(
            #     [random.choice(string.digits + string.ascii_lowercase) for _ in range(ITERATIONS * max(sizes))])
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

# base 32 results
# 14 = (0.6129514172248537, 0.025540110754109918)
# 15 = (0.661117173967326, 0.024764751924602035)
# 16 = (0.7042298057406772, 0.022285838165961424)
# 17 = (0.7422045302481879, 0.020271422491006566)
# 23 = (0.889855888466385, 0.010940856271033712)
# 24 = (0.9046724917605209, 0.009210794985280529)
# 25 = (0.9175641812168194, 0.008701247901329597)
# 26 = (0.9287982291145007, 0.0073638351826790195)
