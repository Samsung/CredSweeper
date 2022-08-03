# Fuzzing of CredSweeper API

The directory is used for dynamic analysis of CredSweeper with using [atheris](https://github.com/google/atheris),
based on [LibFuzzer](https://llvm.org/docs/LibFuzzer.html#options)


## Preparation

- The same interpreter packages as for CredSweeper + atheris + coverage (optional).
Working dir is project root - to be sure current source of credsweeper is used for coverage.
Preferred to use virtual environment.

```bash
python3.8 -m virtualenv --copies .venv
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```


## Fuzzing

Launch fuzzing script to collect seed files. 
```bash
fuzzing.sh
```
-atheris_runs - must be greater than corpus files in 'corpus' directory.
Many interactions require more rss memory - the limit must be decided.
Then after productive fuzzing there will be new corpus files.
Some of them are reduced from others. Some - new for imported libs.
The launch does not require coverage module but requires instumentation.


## Coverage

Launch fuzzing script to calculate coverage with provided corpus files. 
```bash
coveraging.sh
```
To generate HTML report use ```coverage html``` in project root (where .coverage file exists) after fuzzing.
Instrumentation does not required - so it can be skipped.


## Reducing

Launch reducing script to reduce corpus files only for 'NEW'. 
```bash
reducing.sh
```
The script is used -merge function of libfuzzer to reduce corpus files with multiple interaction.
Full instrumentation is preferred.


## Minimizing

Launch the script to remove corpus files that do not impact on credsweeper. 
```bash
minimizing.sh
```
The script uses coverage package to determine which corpus files do not change overall coverage and removes them.
The process is slow due each corpus file has to be checked. Instrumentation is not necessary.

NOTE: some seeds may be dropped due complicated expression is assumed like one line/branch.
e.g.:```if 0x01 == a[0] and 0x02 == a[1]:``` then seed [0x01,0x02] is kept, but [0x01,0x00] will be removed.
