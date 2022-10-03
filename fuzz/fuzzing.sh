#!/bin/bash

set -x
set -e

THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

CORPUS_DIR=fuzz/corpus

# DO instrument to find new seeds
export DO_ATHERIS_INSTRUMENT=1

# make seed from CRC32 of source files to keep the same sequence
seed=0
for f in $(find credsweeper -iregex '.*\.\(py\|json\|yaml\|txt\|onnx\)$'); do
    file_crc32_hex=$(crc32 $f)
    file_crc32_int=$((16#${file_crc32_hex}))
    seed=$(( ${seed} ^ ${file_crc32_int} ))
    done

printf 'CRC32: %x\n' $seed

python -m fuzz \
    -rss_limit_mb=6500 \
    -seed=${seed} \
    -atheris_runs=$(( 150000 + $(ls ${CORPUS_DIR} | wc -l) )) \
    -verbosity=1 \
    ${CORPUS_DIR} \
    ;

# Multithreading with -fork=$(nproc) may be not efficient due overhead for merging
