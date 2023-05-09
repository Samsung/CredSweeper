from pathlib import Path

from credsweeper.app_path import APP_PATH

# total number of files in test samples
SAMPLES_FILES_COUNT: int = 80

# credentials count after scan with ml_threshold = 0 and before post-processing
# check whether all samples are added to git - otherwise it may deviate with skipping ignorable
SAMPLES_CRED_COUNT: int = 72

# credentials count after post-processing with default arguments
# applied in test_app and test_main for whole "test/samples" dir
SAMPLES_POST_CRED_COUNT: int = 65

# archived credentials that not found without --depth
SAMPLES_IN_DEEP_1 = 16
SAMPLES_IN_DEEP_2 = SAMPLES_IN_DEEP_1 + 7
SAMPLES_IN_DEEP_3 = SAMPLES_IN_DEEP_2 + 1

SAMPLES_FILTERED_BY_POST_COUNT = 1

# well known string with all latin letters
AZ_DATA = b"The quick brown fox jumps over the lazy dog"
AZ_STRING = AZ_DATA.decode(encoding="ascii")

# tests directory - use ONLY this file relevance for "release_test" workflow
TESTS_PATH = Path(__file__).resolve().parent
# test samples directory
SAMPLES_PATH = TESTS_PATH / "samples"
