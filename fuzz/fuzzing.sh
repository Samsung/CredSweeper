#!/bin/bash

set -x
set -e

THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

CORPUS_DIR=fuzz/corpus

# DO instrument to find new seeds
export DO_ATHERIS_INSTRUMENT=1

# make seed from current unix time
seed=$(date +%s)
echo "SEED: $seed"

python -m fuzz \
    -rss_limit_mb=6500 \
    -seed=${seed} \
    -atheris_runs=$(( 65536 + $(ls -1 ${CORPUS_DIR} | wc -l) )) \
    -verbosity=1 \
    ${CORPUS_DIR} \
    ;

# Multithreading with -fork=$(nproc) may be not efficient due overhead for merging
