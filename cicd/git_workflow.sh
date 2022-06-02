#!/bin/bash
set -e

if [ -z "${GIT_ANCESTOR}" ]; then
    echo "GIT_ANCESTOR is empty!"
    exit 1
fi

head_hash=$(git log --pretty=%H -n 1 HEAD)
ancestor_hash=$(git log --pretty=%H -n 1 ${GIT_ANCESTOR})

if ! git merge-base --is-ancestor ${ancestor_hash} ${head_hash}; then
    echo "${ancestor_hash} is not ancestor of ${head_hash}"
    exit 1
fi

declare -A commits

function git_test()
{
    echo -e -n "\ntest for ${1}"

    if [ "${ancestor_hash}" == "${1}" ]; then
        echo "This commit is searched ${ancestor_hash}"
        return 0
    fi

    if [ -v commits[${1}] ]; then
        echo -n " - already checked"
        return 0
    else
        echo -n " - need investigation"
        commits[${1}]+=1
    fi

    local has_parents=false
    for commit in $(git log --pretty=%P -n 1 ${1}); do
        has_parents=true
        echo -n " - parent: ${commit}"
        if ! git_test ${commit}; then
            echo " - commit ${commit} fail"
            return 1
        fi
    done

    if ! ${has_parents}; then
        echo " - the end. Commit ${1} has no parents"
        return 1
    fi

    echo "end"
    return 0
}

if ! git_test ${head_hash}; then
    echo "FAIL: ${head_hash} is not pure rebased to ${ancestor_hash}"
    exit 1
fi

echo "OK"

exit 0
