import statistics
from typing import Tuple, Dict


class HopStat:
    """Statistical check distances between symbols sequence in a value on keyboard layout"""

    KEYBOARD = (  #
        "`1234567890-=",  #
        "\0qwertyuiop[]\\",  #
        "\0\0asdfghjkl;'",  #
        "\0\0zxcvbnm,./",  #
    )
    TRANSLATION = str.maketrans({
        '~': '`',
        '!': '1',
        '@': '2',
        '#': '3',
        '$': '4',
        '%': '5',
        '^': '6',
        '&': '7',
        '*': '8',
        '(': '9',
        ')': '0',
        '_': '-',
        '+': '=',
        'Q': 'q',
        'W': 'w',
        'E': 'e',
        'R': 'r',
        'T': 't',
        'Y': 'y',
        'U': 'u',
        'I': 'i',
        'O': 'o',
        'P': 'p',
        '{': '[',
        '}': ']',
        '|': '\\',
        'A': 'a',
        'S': 's',
        'D': 'd',
        'F': 'f',
        'G': 'g',
        'H': 'h',
        'J': 'j',
        'K': 'k',
        'L': 'l',
        ':': ';',
        '"': "'",
        'Z': 'z',
        'X': 'x',
        'C': 'c',
        'V': 'v',
        'B': 'b',
        'N': 'n',
        'M': 'm',
        '<': ',',
        '>': '.',
        '?': '/',
    })

    def __init__(self):
        self.__hop_dict: Dict[Tuple[str, str], int] = {}
        base = ''.join(x for x in HopStat.KEYBOARD)
        for a in (x for x in base if '\0' != x):
            for b in (x for x in base if '\0' != x):
                if (b, a) in self.__hop_dict:
                    self.__hop_dict[(a, b)] = self.__hop_dict[(b, a)]
                    continue
                if a == b:
                    self.__hop_dict[(a, b)] = 0
                else:
                    x_a, y_a, z_a = self.__get_xyz(a)
                    x_b, y_b, z_b = self.__get_xyz(b)
                    d = (abs(x_a - x_b) + abs(y_a - y_b) + abs(z_a - z_b)) // 2
                    self.__hop_dict[(a, b)] = d

    @staticmethod
    def __get_xyz(c: str) -> Tuple[int, int, int]:
        """Returns axial coordinates of a char on keyboad qwerty"""
        x = y = z = 0
        for i, _ in enumerate(HopStat.KEYBOARD):
            x = HopStat.KEYBOARD[i].find(c)
            if 0 <= x:
                z = i
                x = x - (i // 2)
                y = -(z + x)
                break
        return x, y, z

    def stat(self, value: str) -> Tuple[float, float]:
        """Calculates statistical distances between given symbols

        Args:
            value: string based on initial alphabet

        Return:
            Average distance, deviation or exception if a value is not in initial alphabet

        """
        hops = []
        value = value.translate(HopStat.TRANSLATION)
        for a, b in zip(value[:-1], value[1:]):
            hop = self.__hop_dict.get((a, b))
            if hop is None:
                raise ValueError(f"Unknown char '{a}' or '{b}'")
            hops.append(hop)
        avg = statistics.mean(hops)
        dev = statistics.stdev(hops, avg)
        return avg, dev
