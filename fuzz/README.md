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
pip install .[ml]
pip install atheris coverage
```


## Fuzzing

Launch fuzzing script to collect corpus files. 
```bash
fuzzing.sh
```
-atheris_runs - must be greater than corpus files in 'corpus' directory.
Many interactions require more rss memory - the limit must be decided.
Then after productive fuzzing there will be new corpus files.
Some of them are reduced from others. Some - new for imported libs.


## Reducing

Launch reducing script to reduce corpus files only for 'NEW'. 
```bash
reducing.sh
```
The script is used -merge function of libfuzzer to reduce corpus files with multiple interaction.


## Minimizing

Launch the script to remove corpus files that do not impact on credsweeper. 
```bash
minimizing.sh
```
The script uses coverage package to determine which corpus files do not change overall coverage and removes them.
The process is slow due each corpus file has to be checked. 
