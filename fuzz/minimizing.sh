#!/bin/bash

#set -x
set -e

START_TIME=$(date +%s)
echo ">>> START ${BASH_SOURCE[0]} in $(pwd) at $(date)"
THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

cp -vf fuzz/__main__.py .minimizing.py

CORPUS_DIR=fuzz/corpus
MINIMIZING_DIR=fuzz/.corpus.minimizing

rm -vrf ${MINIMIZING_DIR}

mkdir -vp ${MINIMIZING_DIR}

# ## freeze original coverage

rm -rf ${MINIMIZING_DIR}/htmlcov

rm -vf .coverage

python -m coverage run \
    --source=credsweeper \
    .minimizing.py \
    -rss_limit_mb=2048 \
    -atheris_runs=$(( 1 + $(ls ${CORPUS_DIR} | wc -l) )) \
    -verbosity=1 \
    ${CORPUS_DIR}/ \
    ;

python -m coverage report >${MINIMIZING_DIR}/report.txt
original_cov="$(tail -1 ${MINIMIZING_DIR}/report.txt)"

if [ -n "${PRODUCE_HTML}" ]; then
    python -m coverage html
    mv htmlcov ${MINIMIZING_DIR}
fi

# ## run minimization for all corpuses

declare -a CORPUS

i=0
for f in $(ls -S ${CORPUS_DIR}); do
    CORPUS[$i]+=$f
    i=$(( 1 + $i ))
done

for f in ${CORPUS[@]}; do

    echo "test $f"
    mv -vf ${CORPUS_DIR}/$f ${MINIMIZING_DIR}/

    python -m coverage run \
        --source=credsweeper \
        .minimizing.py \
        -rss_limit_mb=2048 \
        -atheris_runs=$(( 1 + $(ls ${CORPUS_DIR} | wc -l) )) \
        -verbosity=1 \
        ${CORPUS_DIR}/ \
        ;
    if [ -n "${PRODUCE_HTML}" ]; then
        python -m coverage html
        mv htmlcov ${MINIMIZING_DIR}/$f.htmlcov
    fi
    python -m coverage report >${MINIMIZING_DIR}/$f.txt
    test_cov="$(tail -1 ${MINIMIZING_DIR}/$f.txt)"
    if [ "$test_cov" != "$original_cov" ]; then
        echo "seed file $f impacts on coverage"
        cp -vf ${MINIMIZING_DIR}/$f ${CORPUS_DIR}/
    else
        echo "seed file $f does not impact on coverage"
    fi

done

SPENT_TIME=$(date -ud "@$(( $(date +%s) - ${START_TIME} ))" +"%H:%M:%S")
echo "<<< DONE ${BASH_SOURCE[0]} in $(pwd) at $(date) elapsed ${SPENT_TIME}"
