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
for f in $(ls corpus); do
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
        -rss_limit_mb=2048 \
        -atheris_runs=$(ls corpus | wc -l) \
        -verbosity=1 \
        corpus/ \
        ;

    test_cov="$(python -m coverage report | tail -1)"
    if [ "$test_cov" != "$original_cov" ]; then
        # the corpus impacts on coverage
        mv -vf $MINDIR/$f/$f corpus/
        python -m coverage html
        mv htmlcov $MINDIR/$f/
    else
        # the corpus does not impact on coverage
        python -m coverage report >$MINDIR/$f/report.txt
    fi

done
