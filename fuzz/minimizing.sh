#!/bin/bash

set -x
set -e

THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

CORPUS_DIR=fuzz/corpus
MINIMIZING_DIR=fuzz/.corpus.minimizing

rm -vrf ${MINIMIZING_DIR}

mkdir -vp ${MINIMIZING_DIR}

# ## freeze original coverage

rm -rf ${MINIMIZING_DIR}/htmlcov

rm -vf .coverage

python -m coverage run \
    --source=credsweeper \
    fuzz \
    -rss_limit_mb=2048 \
    -atheris_runs=$(( 1 + $(ls ${CORPUS_DIR} | wc -l) )) \
    -verbosity=1 \
    ${CORPUS_DIR}/ \
    ;

original_cov="$(python -m coverage report | tail -1)"

python -m coverage html

mv htmlcov ${MINIMIZING_DIR}

# ## run minimization for all corpuses

declare -a CORPUS

i=0
for f in $(ls -S ${CORPUS_DIR}); do
    CORPUS[$i]+=$f
    i=$(( 1 + $i ))
done

for f in ${CORPUS[@]}; do

    echo "test $f"
    mkdir -vp ${MINIMIZING_DIR}/$f
    mv -vf ${CORPUS_DIR}/$f ${MINIMIZING_DIR}/$f/

    python -m coverage run \
        --source=credsweeper \
        fuzz \
        -rss_limit_mb=2048 \
        -atheris_runs=$(( 1 + $(ls ${CORPUS_DIR} | wc -l) )) \
        -verbosity=1 \
        ${CORPUS_DIR}/ \
        ;

    python -m coverage html
    mv htmlcov ${MINIMIZING_DIR}/$f/
    python -m coverage report >${MINIMIZING_DIR}/$f/report.txt
    test_cov="$(tail -1 ${MINIMIZING_DIR}/$f/report.txt)"
    if [ "$test_cov" != "$original_cov" ]; then
        echo "seed file $f impacts on coverage"
        cp -v ${MINIMIZING_DIR}/$f/$f ${CORPUS_DIR}/
    else
        echo "seed file $f does not impact on coverage"
    fi

done
