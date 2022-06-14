#!/bin/bash

set -x
set -e

THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

rm -vf .coverage

python -m coverage run \
    --source=credsweeper \
    fuzz \
    -max_len=1024 \
    -rss_limit_mb=2048 \
    -atheris_runs=$(ls corpus | wc -l) \
    -verbosity=1 \
    corpus/ \
    ;

python -m coverage report
