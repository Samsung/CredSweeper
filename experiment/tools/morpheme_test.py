import random
import signal
import threading
import time
from multiprocessing import Pool
from typing import Tuple, Dict

from credsweeper.common import KeywordChecklist
from credsweeper.common.constants import BASE64COMMON

random_data: str
ITERATIONS = 1000


class KeywordChecklistTest(KeywordChecklist):

    def calc(self, line_lower: str) -> int:
        matches = 0
        for keyword in self.morpheme_set:
            if keyword in line_lower:
                matches += 1
        return matches


counter = KeywordChecklistTest()


def pool_initializer() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def evaluate_avg(_args: Tuple[int, float, float]) -> Tuple[float, float]:
    min_avg = _args[1]
    max_dvt = _args[2]
    size = _args[0]
    for x in range(ITERATIONS):
        offset = x * size
        value = counter.calc(random_data[offset:offset + size])
        if 0 < value < min_avg:
            min_avg = value
        if value > max_dvt:
            max_dvt = value
    return min_avg, max_dvt


if __name__ == "__main__":
    random.seed()
    stats: Dict[int, Tuple[float, float]] = {}
    sizes = [4, 8, 16, 32, 40, 64, 70, 80, 90, 100, 128, 256, 512, 1024]
    try:
        for n in range(100):
            start_time = time.time()
            random_data = ''.join([random.choice(BASE64COMMON) for _ in range(ITERATIONS * max(sizes))])
            _args = [(i, stats[i][0] if i in stats else 9.9, stats[i][1] if i in stats else 0.0) for i in sizes]
            with Pool(processes=min(15, len(_args)), initializer=pool_initializer) as pool:
                for _size, _res in zip(sizes, pool.map(evaluate_avg, _args)):
                    with threading.Lock():
                        stats[_size] = _res
            for k, v in stats.items():
                print(f"{k}: {v}", flush=True)
            print(f"loop {n} in {time.time() - start_time}", flush=True)
    except KeyboardInterrupt as exc:
        print(exc, flush=True)
    finally:
        print("===========================================================", flush=True)
    for k, v in stats.items():
        # for parametrization of unit tests
        print(f"({k}, {v[0]}, {v[1]}),", flush=True)
