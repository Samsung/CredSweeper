#!/bin/bash

#set -x
set -e

START_TIME=$(date +%s)
echo ">>> START ${BASH_SOURCE[0]} in $(pwd) at $(date)"
THISDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null 2>&1 && pwd )"
PARENTDIR="$(dirname ${THISDIR})"

CORPUS_DIR=fuzz/corpus

# copy all current samples as additional seeds
cp -vf $PARENTDIR/tests/samples/* $PARENTDIR/$CORPUS_DIR/

# DO instrument to find new seeds with multiple jobs - effective for small set of initial seeds (corpus)
export DO_ATHERIS_INSTRUMENT=1
# copy the script to apply multijob fuzzing
cp -vf ${THISDIR}/__main__.py ${PARENTDIR}/.fuzzing.py
cd ${PARENTDIR}
# workers would be equal jobs obviously or it takes unpredictable time
if [ 4 -le $(nproc) ]; then
    PROCESSES_NUMBER=$(( $(nproc) / 4 ))
else
    PROCESSES_NUMBER=1
fi
./.fuzzing.py \
    -rss_limit_mb=6500 \
    -runs=$(( 1000 + $(ls -1 ${CORPUS_DIR} | wc -l) )) \
    -verbosity=1 \
    -jobs=${PROCESSES_NUMBER} \
    -workers=${PROCESSES_NUMBER} \
    ${CORPUS_DIR} \
    ;
# clean-up
rm -vf ${PARENTDIR}/.fuzzing.py
# skip to avoid instrumentation during minimization
unset DO_ATHERIS_INSTRUMENT

# do reducing in single step
cd ${THISDIR}
(./reducing.sh)

# minimization with splitting by first letter of seeds files - 8 jobs
declare -A JOBS
for n in $(seq 0 15); do
    x=$(( 15 - ${n} ))
    j=$(printf "%01x" ${x})
    t=$(printf "%01x" $(( (${x} / 2) * 2 )))
    TARGETDIR=${THISDIR}/${t}
    mkdir -vp ${TARGETDIR}/fuzz/corpus
    cp -r ${PARENTDIR}/credsweeper ${TARGETDIR}/
    cp -v ${PARENTDIR}/.coveragerc ${TARGETDIR}/
    cp -v ${PARENTDIR}/fuzz/__main__.py ${TARGETDIR}/fuzz/
    cp -v ${PARENTDIR}/fuzz/minimizing.sh ${TARGETDIR}/fuzz/
    for f in $(find ${PARENTDIR}/${CORPUS_DIR} -type f -name "${j}*"); do mv -vf ${f} ${TARGETDIR}/${CORPUS_DIR}/; done
    if [ "${t}" == "${j}" ]; then
        cd ${TARGETDIR}/fuzz
        (nohup bash -c "./minimizing.sh") &
        job_id=$!
        JOBS[${j}]=${job_id}
    fi
    cd ${THISDIR}
done

BUSY=8
# wait for job finishing
while [ 0 -ne ${BUSY} ]; do
    i=$(( ${BUSY} * 10 ))
    echo -en "\nSleep seconds:"
    while [ 0 -lt $i ]; do
        echo -n " $i"
        i=$(( ${i} - 1 ))
        sleep 1
    done
    BUSY=0
    echo -en "\nCheck jobs:"
    for x in $(seq 0 15); do
        j=$(printf "%01x" ${x})
        job_id=${JOBS[$j]}
        if [ -z "${job_id}" ]; then
            continue
        elif kill -0 ${job_id}; then
            BUSY=$(( 1 + ${BUSY} ))
            echo -n " job $j is alive"
        else
            echo -n " job $j has done"
        fi
    done
done

unset JOBS

# collect
for x in $(seq 0 15); do
    j=$(printf "%01x" ${x})
    TARGETDIR=${THISDIR}/${j}
    for f in $(find ${TARGETDIR}/${CORPUS_DIR} -type f); do mv -vf ${f} ${PARENTDIR}/${CORPUS_DIR}/; done
    rm -rf ${TARGETDIR}
done

# last minimization
cd ${THISDIR}
(./minimizing.sh)

SPENT_TIME=$(date -ud "@$(( $(date +%s) - ${START_TIME} ))" +"%H:%M:%S")
echo "<<< DONE ${BASH_SOURCE[0]} in $(pwd) at $(date) elapsed ${SPENT_TIME}"
