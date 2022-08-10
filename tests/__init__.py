# total number of files in test samples, included .gitignore
SAMPLES_FILES_COUNT: int = 46

# credentials count after scan
SAMPLES_CRED_COUNT: int = 48
SAMPLES_CRED_LINE_COUNT: int = 51

# credentials count after post-processing
SAMPLES_POST_CRED_COUNT: int = 18

# archived credentials that not found without --depth
SAMPLES_IN_DEEP_1 = 2
SAMPLES_IN_DEEP_2 = 3
SAMPLES_IN_DEEP_3 = 4

# well known string with all latin letters
AZ_DATA = b"The quick brown fox jumps over the lazy dog"
AZ_STRING = AZ_DATA.decode(encoding="ascii")
