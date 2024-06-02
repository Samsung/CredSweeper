import binascii
import random
import string
import sys

OLD_SEED_SIZE = 2048
NEW_SEED_SIZE = 4096 - 256


# run in fuzz: for f in $(find corpus -type f); do python3 auxilary.py $f; done

def main(argv):
    ascii_chars = string.digits + string.ascii_letters + string.punctuation + ' '
    responses = [
        b'{"status":"PASS"}',
        b'{"status":"REQUEST_DENIED","error_message":"The provided API key is invalid."}',
        b'{"status":"REQUEST_DENIED","error_message":"This API project is not authorized to use this API."}',
        b'{"ok":1}',
        b'{"error":1}',
        b'{"error":"invalid_auth"}',
        b'<body>You are being <a>redirected',
        b'Unable to find client by that `client_id`',
        b'{"error":{"message":null}}',
        b'{"error":{"message":""}}',
        b"""{"error":{"message":"The provided key 'rk_xxxHaving the 'rak_charge_read'"""
        b""" permission would allow this request to continue."}}""",
    ]
    for i in argv[1:]:
        with open(i, "rb") as f:
            data = f.read()
        for n, x in enumerate(responses):
            data_size = OLD_SEED_SIZE if OLD_SEED_SIZE < len(data) else len(data)
            with open(f"{i}.{n}", "wb") as f:
                f.write(data[:data_size])
                f.write(b'\n' * (NEW_SEED_SIZE - data_size))
                f.write(x)
        crc32 = binascii.crc32(data)
        random.seed(crc32)
        text = ''.join(random.choice(ascii_chars) for _ in range(NEW_SEED_SIZE))
        with open(f"{i}.{crc32:08x}", "w") as f:
            f.write(text)


if __name__ == "__main__":
    main(sys.argv)
