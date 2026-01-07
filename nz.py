import base64
import zlib

with open('tar.tar','rb') as f:
    data=f.read()
print(base64.b64encode( zlib.compress(data)))
