from pathlib import Path

# total number of files in test samples
SAMPLES_FILES_COUNT: int = 102

# credentials count after scan
SAMPLES_CRED_COUNT: int = 97
SAMPLES_CRED_LINE_COUNT: int = 101

# credentials count after post-processing
SAMPLES_POST_CRED_COUNT: int = 91

# with option --doc
SAMPLES_IN_DOC = 67

# archived credentials that not found without --depth
SAMPLES_IN_DEEP_1 = SAMPLES_POST_CRED_COUNT + 15
SAMPLES_IN_DEEP_2 = SAMPLES_IN_DEEP_1 + 7
SAMPLES_IN_DEEP_3 = SAMPLES_IN_DEEP_2 + 1

# well known string with all latin letters
AZ_DATA = b"The quick brown fox jumps over the lazy dog"
AZ_STRING = AZ_DATA.decode(encoding="ascii")

# tests directory - use ONLY this file relevance for "release_test" workflow
TESTS_PATH = Path(__file__).resolve().parent
# test samples directory
SAMPLES_PATH = TESTS_PATH / "samples"
