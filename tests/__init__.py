from pathlib import Path

# total number of files in test samples
SAMPLES_FILES_COUNT = 175

# ML_DELTA for different platforms which may produce a dribbling in ml_probability
ML_DELTA = 0.0001

# float value of ML threshold is used to display possible lowest values
ZERO_ML_THRESHOLD = 0.0

# with option --doc & NEGLIGIBLE_ML_THRESHOLD
SAMPLES_IN_DOC = 927

# credentials count after scan without filters and ML validations
SAMPLES_REGEX_COUNT = 661

# credentials count after scan with filters and without ML validation
SAMPLES_FILTERED_COUNT = 547

# credentials count after default post-processing
SAMPLES_POST_CRED_COUNT = 501

# archived credentials that are not found without --depth
SAMPLES_IN_DEEP_1 = SAMPLES_POST_CRED_COUNT + 138
SAMPLES_IN_DEEP_2 = SAMPLES_IN_DEEP_1 + 5
SAMPLES_IN_DEEP_3 = SAMPLES_IN_DEEP_2 + 4

# well known string with all latin letters
AZ_DATA = b"The quick brown fox jumps over the lazy dog"
# Assume, there should be only ASCII symbols
AZ_STRING = AZ_DATA.decode(encoding="ascii", errors="strict")

# tests directory - use ONLY this file relevance for "release_test" workflow
TESTS_PATH = Path(__file__).resolve().parent
# test samples directory
SAMPLES_PATH = TESTS_PATH / "samples"
SAMPLE_TAR = SAMPLES_PATH / "pem_key.tar"
SAMPLE_ZIP = SAMPLES_PATH / "pem_key.zip"
SAMPLE_HTML = SAMPLES_PATH / "test.html"
SAMPLE_DOCX = SAMPLES_PATH / "sample.docx"
SAMPLE_PY = SAMPLES_PATH / "sample.py"
SAMPLE_DEB = SAMPLES_PATH / "sample.deb"
SAMPLE_SQLITE = SAMPLES_PATH / "sample.sqlite"
