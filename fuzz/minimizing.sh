#!/bin/bash

set -x
set -e

THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
cd "${THISDIR}/.."

MINDIR=.minimizing

mkdir -vp $MINDIR

# ## freeze original coverage

rm -rf $MINDIR/htmlcov

rm -vf .coverage

python -m coverage run --source=credsweeper  fuzz -rss_limit_mb=2048 -atheris_runs=$(ls corpus | wc -l) -verbosity=1 corpus/

original_cov="$(python -m coverage report | tail -1)"

python -m coverage html

mv htmlcov $MINDIR

# ## run minimization for all corpuses

declare -a CORPUS

i=0
for f in $(ls corpus | shuf); do
    CORPUS[$i]+=$f
    i=$(( 1 + $i ))
done

for f in ${CORPUS[@]}; do

    echo "test $f"
    mkdir -vp $MINDIR/$f
    mv -vf corpus/$f $MINDIR/$f/

    python -m coverage run \
        --source=credsweeper \
        fuzz \
        -max_len=1024 \
        -rss_limit_mb=2048 \
        -atheris_runs=$(ls corpus | wc -l) \
        -verbosity=1 \
        corpus/ \
        ;

    python -m coverage html
    mv htmlcov $MINDIR/$f/
    python -m coverage report >$MINDIR/$f/report.txt
    test_cov="$(tail -1 $MINDIR/$f/report.txt)"
    if [ "$test_cov" != "$original_cov" ]; then
        echo "corpus $f impacts on coverage"
        cp -v $MINDIR/$f/$f corpus/
    else
        echo "corpus $f does not impact on coverage"
    fi

done
