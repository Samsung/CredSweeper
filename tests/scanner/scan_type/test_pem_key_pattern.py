from credsweeper.scanner.scan_type import PemKeyPattern


class TestPemKeyPattern:

    def test_remove_leading_config_lines_p(self):
        lines = [
            "Proc-Type: 4,ENCRYPTED", "DEK-Info: DES-EDE3-CBC,BA2D3F11273F6I7A", "",
            "MIIh6AIBAAKCB4EAxDqYteAJG3fdG0yiot3UBzU9Z8beAp0FvLd0gR15pJAlSQ+G"
        ]
        filtered_lines = PemKeyPattern.remove_leading_config_lines(lines)
        assert len(filtered_lines) == 1
        assert filtered_lines[0] == lines[-1]

    def test_remove_leading_config_lines_n(self):
        lines = [
            "MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp",
            "wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5",
            "1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh"
        ]
        filtered_lines = PemKeyPattern.remove_leading_config_lines(lines)
        assert len(filtered_lines) == len(lines)

    def test_strip_lines_p(self):
        lines = [
            "    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCqx5mEeaMNCqr",
            "  'hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n\n' +",
            "  'hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n\\n' +",
            "#    hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n"
        ]
        should_be = [
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCqx5mEeaMNCqr",
            "hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n",
            "hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n",
            "hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n"
        ]
        filtered_lines = PemKeyPattern.strip_lines(lines)
        assert all(l1 == l2 for l1, l2 in zip(filtered_lines, should_be))

    def test_strip_lines_n(self):
        """Check that valid PEM lines will not be changed"""
        lines = [
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCqx5mEeaMNCqr",
            "hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n"
        ]
        filtered_lines = PemKeyPattern.strip_lines(lines)
        assert all(l1 == l2 for l1, l2 in zip(filtered_lines, lines))
