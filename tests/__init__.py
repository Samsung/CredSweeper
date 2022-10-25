from pathlib import Path

# total number of files in test samples, included .gitignore
SAMPLES_FILES_COUNT: int = 52

# credentials count after scan
SAMPLES_CRED_COUNT: int = 51
SAMPLES_CRED_LINE_COUNT: int = 54

# credentials count after post-processing
SAMPLES_POST_CRED_COUNT: int = 20

# archived credentials that not found without --depth
SAMPLES_IN_DEEP_1 = 5
SAMPLES_IN_DEEP_2 = 6
SAMPLES_IN_DEEP_3 = 7

SAMPLES_FILTERED_BY_POST_COUNT = 1

# well known string with all latin letters
AZ_DATA = b"The quick brown fox jumps over the lazy dog"
AZ_STRING = AZ_DATA.decode(encoding="ascii")

# root directory of the project
PROJECT_DIR = Path(__file__).resolve().parent.parent
# CredSweeper/tests directory
TESTS_DIR = PROJECT_DIR / "tests"
# test samples directory
SAMPLES_DIR = TESTS_DIR / "samples"
