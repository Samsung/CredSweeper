import sys


def main(argv):
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
        b'{"error":{"message":"The provided key \'rk_xxxHaving the \'rak_charge_read\' permission would allow this request to continue."}}',
    ]
    for i in argv[1:]:
        with open(i, "rb") as f:
            data = f.read()
        for n, x in enumerate(responses):
            with open(f"{i}.{n}", "wb") as f:
                if 0x800 < len(data):
                    f.write(data[:0x800])
                    f.write(x)
                else:
                    f.write(data)
                    f.write(b'\n' * (0x800 - len(data)))
                    f.write(x)


if __name__ == "__main__":
    main(sys.argv)
