import random
import string
from os.path import dirname, join

from credsweeper.utils import Util

PASSWORDS_PATH = join(dirname(__file__), "dictionaries/passwords10000.txt")


class Chars:
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    HEX_CHARS = "1234567890abcdefABCDEF"
    BASE36_CHARS = "abcdefghijklmnopqrstuvwxyz1234567890"


class SecretCreds:

    def __init__(self):
        self.passwords = self.load_passwords(PASSWORDS_PATH)

    @staticmethod
    def load_passwords(path):
        """Load password samples

        Password samples based on typical password from https://github.com/danielmiessler/SecLists and
        own sets of passwords obtained during the collection of the dataset
        """
        lines = Util.read_file(path)
        passwords = [line.rstrip() for line in lines if ' ' not in line]
        return passwords

    @staticmethod
    def generate_secret():
        """Generates random secret with random length"""
        string_set = string.ascii_lowercase + string.ascii_uppercase + string.digits
        secret = ''.join(random.choices(string_set, k=random.randint(12, 32)))
        return secret

    def get_password(self):
        """Get password sample"""
        password = random.choice(self.passwords)
        return password


def get_obfuscated_value(value, pattern):
    obfuscated_value = ""
    if pattern == "AWS Client ID" or value.startswith("AKIA"):  # AKIA, AIPA, ASIA, AGPA, ...
        obfuscated_value = value[:4] + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    elif pattern == "Google API Key":  # AIza
        obfuscated_value = "AIza" + ''.join(random.choices(string.ascii_letters + string.digits + "-" + "_", k=35))
    elif pattern == "Google OAuth Access Token":  # ya29.
        obfuscated_value = "ya29." + obfuscate_value(value[5:])
    elif pattern == "Twilio API Key":
        obfuscated_value = "SK" + ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    elif pattern == "JSON Web Token":  # eyJ
        header = "eyJ" + obfuscate_value(value.split(".")[0][3:])
        obfuscated_value = header
        if len(value.split(".")) >= 2:
            payload = "eyJ" + obfuscate_value(value.split(".")[1][3:])
            obfuscated_value += "." + payload

        if len(value.split(".")) >= 3:  # Signature is optional
            signature = obfuscate_value(value.split(".")[2])
            obfuscated_value += "." + signature
    else:
        obfuscated_value = obfuscate_value(value)

    return obfuscated_value


def obfuscate_value(value):
    obfuscated_value = ""

    for v in value:
        if v in string.ascii_lowercase:
            obfuscated_value += random.choice(string.ascii_lowercase)
        elif v in string.ascii_uppercase:
            obfuscated_value += random.choice(string.ascii_uppercase)
        elif v in string.digits:
            obfuscated_value += random.choice(string.digits)
        else:
            obfuscated_value += v

    return obfuscated_value
