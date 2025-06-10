import random
import signal
import statistics
import threading
import time
from multiprocessing import Pool
from typing import Tuple, Dict

from credsweeper.common.constants import Chars
from credsweeper.utils.util import Util

random_data: str
ITERATIONS = 1000


def pool_initializer() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def evaluate_avg(_args: Tuple[int, float, float]) -> Tuple[float, float]:
    min_avg = _args[1]
    max_dvt = _args[2]
    size = _args[0]
    entropies = []
    for x in range(ITERATIONS):
        offset = x * size
        entropy = Util.get_shannon_entropy(random_data[offset:offset + size])
        entropies.append(entropy)
    avg = statistics.mean(entropies)
    dvt = statistics.stdev(entropies, avg)
    if avg < min_avg:
        min_avg = avg
    if dvt > max_dvt:
        max_dvt = dvt
    return min_avg, max_dvt


if __name__ == "__main__":
    random.seed()
    stats: Dict[int, Tuple[float, float]] = {}
    sizes = [x for x in range(8, 36)]
    try:
        for n in range(1000):
            start_time = time.time()
            random_data = ''.join([random.choice(Chars.BASE32_CHARS.value) for _ in range(ITERATIONS * max(sizes))])
            _args = [(i, stats[i][0] if i in stats else 9.9, stats[i][1] if i in stats else 0.0) for i in sizes]
            with Pool(processes=min(15, len(_args)), initializer=pool_initializer) as pool:
                for _size, _res in zip(sizes, pool.map(evaluate_avg, _args)):
                    with threading.Lock():
                        stats[_size] = _res
            for k, v in stats.items():
                print(f"{k}: {v}", flush=True)
            print(f"loop {n} in {time.time() - start_time}", flush=True)
    except KeyboardInterrupt as exc:
        print(exc)
    finally:
        print("===========================================================")
    for k, v in stats.items():
        # for parametrization of unit tests
        print(f"({k}, {v[0]}, {v[1]}),", flush=True)
