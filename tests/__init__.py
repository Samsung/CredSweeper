# total number of files in test samples, included .gitignore
SAMPLES_FILES_COUNT: int = 43

# credentials count after scan
SAMPLES_CRED_COUNT: int = 50
SAMPLES_CRED_LINE_COUNT: int = 53

# credentials count after post-processing
SAMPLES_POST_CRED_COUNT: int = 18

# well known string with all latin letters
AZ_DATA = b"The quick brown fox jumps over the lazy dog"
AZ_STRING = AZ_DATA.decode(encoding="ascii")
