from credsweeper.credentials import LineData
from credsweeper.filters import Filter


class CreditCardNumberCheck(Filter):
    """Check that value is a credit card number."""

    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            False, if the sequence is not card number. True if it is

        """
        if line_data.value is None \
                or 16 != len(line_data.value) \
                or ("0" == line_data.value[0] and "0" == line_data.value[1]):
            return True
        try:
            s = 0
            # https://en.wikipedia.org/wiki/Luhn_algorithm
            for n in range(0, 16):
                x = int(line_data.value[n])
                if 0 == (1 & n):  # Only for odd numbers (with 0 as a start index)
                    x *= 2
                    if x > 9:
                        x -= 9
                s += x

            if 0 == s % 10:
                return False
        except ValueError:
            pass

        # return False when the sequence is not a credit card number
        return True
