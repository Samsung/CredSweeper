#!/bin/bash

set -x
set -e

THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

python -m fuzz \
    -rss_limit_mb=6000 \
    -seed=$(date +%s) \
    -atheris_runs=$(( 1024 + $(ls corpus | wc -l) )) \
    -verbosity=1 \
    corpus/ \
    ;
