#!/usr/bin/env bash

#set -x
set -e

START_TIME=$(date +%s)
echo ">>> START ${BASH_SOURCE[0]} in $(pwd) at $(date)"
THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

cp -vf fuzz/__main__.py .fuzzing.py

CORPUS_DIR=fuzz/corpus

# DO instrument to find new seeds
export DO_ATHERIS_INSTRUMENT=1

# fuzzing with single thread only
python .fuzzing.py \
    -rss_limit_mb=6500 \
    -atheris_runs=$(( 100000 + $(ls -1 ${CORPUS_DIR} | wc -l) )) \
    -verbosity=1 \
    ${CORPUS_DIR} \
    ;

# Multijob works with -runs, ignoring -atheris_runs !!!

SPENT_TIME=$(date -ud "@$(( $(date +%s) - ${START_TIME} ))" +"%H:%M:%S")
echo "<<< DONE ${BASH_SOURCE[0]} in $(pwd) at $(date) elapsed ${SPENT_TIME}"
