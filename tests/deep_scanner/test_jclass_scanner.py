import base64
import io
import unittest

from credsweeper.deep_scanner.jclass_scanner import JclassScanner
from tests import AZ_DATA

SAMPLE_B64 = """
yv66vgAAAEEAaQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWEgAAAAgMAAkACgEAA3J1bgEAFigpTGphdmEvbGFuZy9S
dW5uYWJsZTsLAAwADQcADgwACQAGAQASamF2YS9sYW5nL1J1bm5hYmxlCQAQABEHABIMABMAFAEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9p
by9QcmludFN0cmVhbTsHABYBAAZTYW1wbGUKABgAGQcAGgwAGwAcAQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BAAQoWilWCgAYAB4MABsAHwEA
BChDKVYIACEBACRiYWNlNGQxOS1iZWVmLWNhZmUtY29vMS05MTI5NDc0YmNkODEKABgAIwwAGwAkAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWBQAAAAB3NhXZ
CgAYACgMABsAKQEABChKKVYGQBdu4XWCSM4KABgALQwAGwAuAQAEKEQpVgoAFQADCgAVAA0IAAkBAAxKQVZBX0JPT0xFQU4BAAFaAQANQ29uc3RhbnRWYWx1
ZQMAAAABAQAJSkFWQV9DSEFSAQABQwMAAABYAQAJSkFWQV9CWVRFAQABQgMAAAB7AQAKSkFXQV9TSE9SVAEAAVMDAAABXgEACEpBVkFfSU5UAQABSQMAAIAA
AQAJSkFWQV9MT05HAQABSgUAAAAAdzWUAAEACkpBVkFfRkxPQVQBAAFGBEBI9cMBAAtKQVZBX0RPVUJMRQEAAUQGQAW/CosEkZsBAAtKQVZBX1NUUklORwEA
EkxqYXZhL2xhbmcvU3RyaW5nOwEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAANsb2cBAARtYWluAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgEADGxhbWJk
YSRydW4kMAEAClNvdXJjZUZpbGUBAAtTYW1wbGUuamF2YQEAEEJvb3RzdHJhcE1ldGhvZHMQAAYPBgBaCgAVAFsMAFQABg8GAF0KAF4AXwcAYAwAYQBiAQAi
amF2YS9sYW5nL2ludm9rZS9MYW1iZGFNZXRhZmFjdG9yeQEAC21ldGFmYWN0b3J5AQDMKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3Vw
O0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL2lu
dm9rZS9NZXRob2RIYW5kbGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7AQAMSW5uZXJDbGFzc2Vz
BwBlAQAlamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cAcAZwEAHmphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcwEABkxvb2t1cAAh
ABUAAgABAAwACQAaADIAMwABADQAAAACADUAGgA2ADcAAQA0AAAAAgA4ABoAOQA6AAEANAAAAAIAOwAaADwAPQABADQAAAACAD4AGgA/AEAAAQA0AAAAAgBB
ABoAQgBDAAEANAAAAAIARAAaAEYARwABADQAAAACAEgAGgBJAEoAAQA0AAAAAgBLABoATQBOAAEANAAAAAIAIAAFAAEABQAGAAEATwAAAB0AAQABAAAABSq3
AAGxAAAAAQBQAAAABgABAAAABAABAAkABgABAE8AAAAtAAEAAgAAAA26AAcAAEwruQALAQCxAAAAAQBQAAAADgADAAAAEgAGABMADAAUAAEAUQAGAAEATwAA
AFYAAwABAAAAKrIADwS2ABeyAA8QWLYAHbIADxIgtgAisgAPFAAltgAnsgAPFAAqtgAssQAAAAEAUAAAABoABgAAABcABwAYAA8AGQAXABoAIAAbACkAHAAJ
AFIAUwABAE8AAAAnAAIAAQAAAAu7ABVZtwAvtgAwsQAAAAEAUAAAAAoAAgAAAB8ACgAgEAoAVAAGAAEATwAAACEAAgAAAAAACbIADxIxtgAisQAAAAEAUAAA
AAYAAQAAABIAAwBVAAAAAgBWAFcAAAAMAAEAXAADAFgAWQBYAGMAAAAKAAEAZABmAGgAGQ==
"""


class TestJclassScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_get_utf8_constants_n(self):
        with self.assertRaises(AttributeError):
            JclassScanner.get_utf8_constants(None)
        with self.assertRaises(Exception):
            JclassScanner.get_utf8_constants(io.BytesIO(b''))
        self.assertListEqual([], JclassScanner.get_utf8_constants(io.BytesIO(AZ_DATA)))

    def test_get_utf8_constants_p(self):
        data = base64.b64decode(SAMPLE_B64)
        self.assertListEqual([
            'java/lang/Object', '<init>', '()V', 'run', '()Ljava/lang/Runnable;', 'java/lang/Runnable',
            'java/lang/System', 'out', 'Ljava/io/PrintStream;', 'Sample', 'java/io/PrintStream', 'println', '(Z)V',
            '(C)V', 'bace4d19-beef-cafe-coo1-9129474bcd81', '(Ljava/lang/String;)V', '(J)V', '(D)V', 'JAVA_BOOLEAN',
            'Z', 'ConstantValue', 'JAVA_CHAR', 'C', 'JAVA_BYTE', 'B', 'JAWA_SHORT', 'S', 'JAVA_INT', 'I', 'JAVA_LONG',
            'J', 'JAVA_FLOAT', 'F', 'JAVA_DOUBLE', 'D', 'JAVA_STRING', 'Ljava/lang/String;', 'Code', 'LineNumberTable',
            'log', 'main', '([Ljava/lang/String;)V', 'lambda$run$0', 'SourceFile', 'Sample.java', 'BootstrapMethods',
            'java/lang/invoke/LambdaMetafactory', 'metafactory',
            ('(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;'
             'Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;'
             ')Ljava/lang/invoke/CallSite;'), 'InnerClasses', 'java/lang/invoke/MethodHandles$Lookup',
            'java/lang/invoke/MethodHandles', 'Lookup'
        ], JclassScanner.get_utf8_constants(io.BytesIO(data[8:])))
