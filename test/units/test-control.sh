# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

declare -i CHILD_PID=0
PASSED_TESTS=()
FAILED_TESTS=()

# Like trap, but passes the signal name as the first argument
trap_with_sig() {
    local fun="${1:?}"
    local sig
    shift

    for sig in "$@"; do
        # shellcheck disable=SC2064
        trap "$fun $sig" "$sig"
    done
}

# Propagate the caught signal to the current child process
handle_signal() {
    local sig="${1:?}"

    if [[ $CHILD_PID -gt 0 ]]; then
        echo "Propagating signal $sig to child process $CHILD_PID"
        kill -s "$sig" "$CHILD_PID"
    fi
}

# In order to make the handle_signal() stuff above work, we have to execute
# each script asynchronously, since bash won't execute traps until the currently
# executed command finishes. This, however, introduces another issue regarding
# how bash's wait works. Quoting:
#
#   When bash is waiting for an asynchronous command via the wait builtin,
#   the reception of a signal for which a trap has been set will cause the wait
#   builtin to return immediately with an exit status greater than 128,
#   immediately after which the trap is executed.
#
# In other words - every time we propagate a signal, wait returns with
# 128+signal, so we have to wait again - repeat until the process dies.
wait_harder() {
    local pid="${1:?}"

    while kill -0 "$pid" &>/dev/null; do
        wait "$pid" || :
    done

    wait "$pid"
}

# Like run_subtests, but propagate specified signals to the subtest script
run_subtests_with_signals() {
    local subtests=("${0%.sh}".*.sh)
    local subtest

    if [[ "${#subtests[@]}" -eq 0 ]]; then
        echo >&2 "No subtests found for file $0"
        exit 1
    fi

    if [[ "$#" -eq 0 ]]; then
        echo >&2 "No signals to propagate were specified"
        exit 1
    fi

    trap_with_sig handle_signal "$@"

    for subtest in "${subtests[@]}"; do
        : "--- $subtest BEGIN ---"
        "./$subtest" &
        CHILD_PID=$!
        wait_harder "$CHILD_PID" && PASSED_TESTS+=("$subtest") || FAILED_TESTS+=("$subtest")
        : "--- $subtest END ---"
    done

    show_summary
}

# Run all subtests (i.e. files named as testsuite-<testid>.<subtest_name>.sh)
run_subtests() {
    local subtests=("${0%.sh}".*.sh)
    local subtest

    if [[ "${#subtests[@]}" -eq 0 ]]; then
        echo >&2 "No subtests found for file $0"
        exit 1
    fi

    for subtest in "${subtests[@]}"; do
        : "--- $subtest BEGIN ---"
        "./$subtest" && PASSED_TESTS+=("$subtest") || FAILED_TESTS+=("$subtest")
        : "--- $subtest END ---"
    done

    show_summary
}

# Run all test cases (i.e. functions prefixed with testcase_ in the current namespace)
run_testcases() {
    local testcase testcases

    # Create a list of all functions prefixed with testcase_
    mapfile -t testcases < <(declare -F | awk '$3 ~ /^testcase_/ {print $3;}')

    if [[ "${#testcases[@]}" -eq 0 ]]; then
        echo >&2 "No test cases found, this is most likely an error"
        exit 1
    fi

    for testcase in "${testcases[@]}"; do
        : "+++ $testcase BEGIN +++"
        # Note: the subshell here is used purposefully, otherwise we might
        #       unexpectedly inherit a RETURN trap handler from the called
        #       function and call it for the second time once we return,
        #       causing a "double-free"
        ("$testcase")
        : "+++ $testcase END +++"
    done
}

show_summary() {(
    set +x

    if [[ ${#PASSED_TESTS[@]} -eq 0 && ${#FAILED_TESTS[@]} -eq 0 ]]; then
        echo >&2 "No tests were executed, this is most likely an error"
        exit 1
    fi

    printf "PASSED TESTS: %3d:\n" "${#PASSED_TESTS[@]}"
    echo   "------------------"
    for t in "${PASSED_TESTS[@]}"; do
        echo "$t"
    done

    if [[ "${#FAILED_TESTS[@]}" -ne 0 ]]; then
        printf "FAILED TESTS: %3d:\n" "${#FAILED_TESTS[@]}"
        echo   "------------------"
        for t in "${FAILED_TESTS[@]}"; do
            echo "$t"
        done
    fi

    [[ "${#FAILED_TESTS[@]}" -eq 0 ]]
)}
