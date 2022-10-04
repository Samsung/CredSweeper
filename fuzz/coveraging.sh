#!/bin/bash

set -x
set -e

THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

CORPUS_DIR=fuzz/corpus

rm -vf .coverage

python -m coverage run \
    --source=credsweeper \
    fuzz \
    -rss_limit_mb=4096 \
    -atheris_runs=$(( 1 + $(ls ${CORPUS_DIR} | wc -l) )) \
    -verbosity=1 \
    ${CORPUS_DIR} \
    ;

# make html report
python -m coverage html
# remove uniq data to compare reports
(cd htmlcov && for f in $(ls . | grep '.*\.html'); do sed -i "s/.*created at.*//g" $f; done)

# report in text format
python -m coverage report
