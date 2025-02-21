import base64
import random
import signal
import statistics
import threading
import time
from multiprocessing import Pool
from typing import Tuple, Dict

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
    entropies = []
    for x in range(ITERATIONS):
        offset = x * size
        # entropy = Util.get_shannon_entropy(random_data[offset:offset + size], Chars.BASE64_CHARS.value)
        # entropy = Util.get_shannon_entropy(random_data[offset:offset + size], Chars.BASE36_CHARS.value)
        entropy = Util.get_shannon_entropy(random_data[offset:offset + size], Chars.BASE32_CHARS.value)
        entropies.append(entropy)
    avg = statistics.mean(entropies)
    dvt = statistics.stdev(entropies, avg)
    if avg < min_avg:
        min_avg = avg
        min_dvt = dvt
    return min_avg, min_dvt


if __name__ == "__main__":

    stats: Dict[int, Tuple[float, float]] = {}
    sizes = [12, 13, 15, 16, 17, 31, 32, 33]
    try:
        for n in range(1000):
            start_time = time.time()
            rand_bytes = random.randbytes(int(8 * ITERATIONS * max(sizes) / 5))
            random_data = base64.b32encode(rand_bytes).decode('ascii')
            # random_data = ''.join(
            #     [random.choice(string.digits + string.ascii_lowercase) for _ in range(ITERATIONS * max(sizes))])
            _args = [(i, stats[i][0] if i in stats else 9.9, stats[i][1] if i in stats else 0.0) for i in sizes]
            with Pool(processes=min(15, len(_args)), initializer=pool_initializer) as pool:
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

# base32
# 12 = (3.2448401902687922, 0.2001867347580528)
# 13 = (3.3305754195719484, 0.1987638281794566)
# 15 = (3.4840904247691813, 0.192504685389475)
# 16 = (3.544861791803441, 0.184688685917545)
# 17 = (3.613827056321014, 0.18707867741897827)
# 31 = (4.15268463818445, 0.1486133074700339)
# 32 = (4.177896164672521, 0.1472328639816872)
# 33 = (4.197883981615083, 0.14735097649694248)

# base36
# 14 = (3.4457644517398167, 0.18990807349700253)
# 15 = (3.5260346505689992, 0.18114901125908447)
# 16 = (3.598032662269341, 0.1830565384431312)
# 17 = (3.659276363856176, 0.1856434289456263)
# 23 = (3.963851572519515, 0.16574824489877288)
# 24 = (4.00254984568254, 0.1623406588528336)
# 25 = (4.040134902813914, 0.158720524449059)
# 26 = (4.078098075953585, 0.15933209429031434)

# base64
# 15 = (3.6775207689256977, 0.15381412670043787)
# 16 = (3.7600552609204625, 0.15666871578775507)
# 17 = (3.835262182966267, 0.1514079815395568)
# 18 = (3.899273202112598, 0.15521615494595756)
# 19 = (3.9669074540527136, 0.15022181070460836)
# 20 = (4.026675938018028, 0.1477139960335224)
# 21 = (4.0844028599694155, 0.14611461336723608)
# 23 = (4.1880028531766245, 0.14668346833164134)
# 24 = (4.236982996273627, 0.14220068825454704)
# 25 = (4.283528241641759, 0.14323971561083385)
# 31 = (4.5121865964712535, 0.1393228408491736)
# 32 = (4.545556887485041, 0.13347416608982715)
# 33 = (4.576938427997454, 0.1300362152603773)
# 39 = (4.743676039379888, 0.13053505168803348)
# 40 = (4.76769110698625, 0.1307074052311964)
