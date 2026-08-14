# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

declare -i _CHILD_PID=0
_PASSED_TESTS=()
_SKIPPED_TESTS=()

# A subtest may exit with this code to report that it skipped itself,
# matching the skip code used by the integration test harness.
_SUBTEST_SKIP_RC=77

# Like trap, but passes the signal name as the first argument
_trap_with_sig() {
    local fun="${1:?}"
    local sig
    shift

    for sig in "$@"; do
        # shellcheck disable=SC2064
        trap "$fun $sig" "$sig"
    done
}

# Propagate the caught signal to the current child process
_handle_signal() {
    local sig="${1:?}"

    if [[ $_CHILD_PID -gt 0 ]]; then
        echo "Propagating signal $sig to child process $_CHILD_PID"
        kill -s "$sig" "$_CHILD_PID"
    fi
}

# In order to make the _handle_signal() stuff above work, we have to execute
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
_wait_harder() {
    local pid="${1:?}"

    while kill -0 "$pid" &>/dev/null; do
        wait "$pid" || :
    done

    wait "$pid"
}

_show_summary() {(
    set +x

    if [[ ${#_PASSED_TESTS[@]} -eq 0 && ${#_SKIPPED_TESTS[@]} -eq 0 ]]; then
        echo >&2 "No tests were executed, this is most likely an error"
        exit 1
    fi

    printf "PASSED TESTS: %3d:\n" "${#_PASSED_TESTS[@]}"
    echo   "------------------"
    for t in "${_PASSED_TESTS[@]}"; do
        echo "$t"
    done

    if [[ ${#_SKIPPED_TESTS[@]} -gt 0 ]]; then
        printf "SKIPPED TESTS: %3d:\n" "${#_SKIPPED_TESTS[@]}"
        echo   "-------------------"
        for t in "${_SKIPPED_TESTS[@]}"; do
            echo "$t"
        done
    fi
)}

_record_subtest_rc() {
    local subtest="${1:?}" rc="${2:?}"

    if [[ $rc -eq $_SUBTEST_SKIP_RC ]]; then
        echo "Subtest $subtest skipped"
        _SKIPPED_TESTS+=("$subtest")
    elif [[ $rc -ne 0 ]]; then
        echo "Subtest $subtest failed"
        return 1
    else
        _PASSED_TESTS+=("$subtest")
    fi
}

# Like run_subtests, but propagate specified signals to the subtest script
run_subtests_with_signals() {
    local subtests=("${0%.sh}".*.sh)
    local subtest rc

    if [[ "${#subtests[@]}" -eq 0 ]]; then
        echo >&2 "No subtests found for file $0"
        exit 1
    fi

    if [[ "$#" -eq 0 ]]; then
        echo >&2 "No signals to propagate were specified"
        exit 1
    fi

    _trap_with_sig _handle_signal "$@"

    for subtest in "${subtests[@]}"; do
        if [[ -n "${TEST_MATCH_SUBTEST:-}" ]] && ! [[ "$subtest" =~ $TEST_MATCH_SUBTEST ]]; then
            echo "Skipping $subtest (not matching '$TEST_MATCH_SUBTEST')"
            continue
        fi

        for skip in ${TEST_SKIP_SUBTESTS:-}; do
            if [[ "$subtest" =~ $skip ]]; then
                echo "Skipping $subtest (matching '$skip')"
                continue 2
            fi
        done

        : "--- $subtest BEGIN ---"
        SECONDS=0
        rc=0
        "./$subtest" &
        _CHILD_PID=$!
        _wait_harder "$_CHILD_PID" || rc=$?
        _record_subtest_rc "$subtest" "$rc" || return 1
        : "--- $subtest END (${SECONDS}s) ---"
    done

    _show_summary
}

# Run all subtests (i.e. files named as $TESTNAME.<subtest_name>.sh)
run_subtests() {
    local subtests=("${0%.sh}".*.sh)
    local subtest rc

    if [[ "${#subtests[@]}" -eq 0 ]]; then
        echo >&2 "No subtests found for file $0"
        exit 1
    fi

    for subtest in "${subtests[@]}"; do
        if [[ -n "${TEST_MATCH_SUBTEST:-}" ]] && ! [[ "$subtest" =~ $TEST_MATCH_SUBTEST ]]; then
            echo "Skipping $subtest (not matching '$TEST_MATCH_SUBTEST')"
            continue
        fi

        for skip in ${TEST_SKIP_SUBTESTS:-}; do
            if [[ "$subtest" =~ $skip ]]; then
                echo "Skipping $subtest (matching '$skip')"
                continue 2
            fi
        done

        : "--- $subtest BEGIN ---"
        SECONDS=0
        rc=0
        "./$subtest" || rc=$?
        _record_subtest_rc "$subtest" "$rc" || return 1
        : "--- $subtest END (${SECONDS}s) ---"
    done

    _show_summary
}

_finalize_subtests() {
    if [[ ${#_PASSED_TESTS[@]} -eq 0 && ${#_SKIPPED_TESTS[@]} -gt 0 ]]; then
        echo "All subtests skipped" | tee --append /skipped
        exit "$_SUBTEST_SKIP_RC"
    fi

    touch /testok
    exit 0
}

# Run all subtests and finalize the test in one shot: exit 77 (skipped) if every subtest skipped,
# otherwise mark success (/testok) and exit. Use this ONLY for tests whose body is just subtests.
# Do NOT use it if the parent script has meaningful test content of its own.
run_subtests_and_exit() {
    run_subtests
    _finalize_subtests
}

# Like run_subtests_and_exit, but propagates the given signals to the subtests (see
# run_subtests_with_signals).
run_subtests_with_signals_and_exit() {
    run_subtests_with_signals "$@"
    _finalize_subtests
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
        if [[ -n "${TEST_MATCH_TESTCASE:-}" ]] && ! [[ "$testcase" =~ $TEST_MATCH_TESTCASE ]]; then
            echo "Skipping $testcase (not matching '$TEST_MATCH_TESTCASE')"
            continue
        fi

        for skip in ${TEST_SKIP_TESTCASES:-}; do
            if [[ "$testcase" =~ $skip ]]; then
                echo "Skipping $testcase (matching '$skip')"
                continue 2
            fi
        done

        : "+++ $testcase BEGIN +++"
        # Note: the subshell here is used purposefully, otherwise we might
        #       unexpectedly inherit a RETURN trap handler from the called
        #       function and call it for the second time once we return,
        #       causing a "double-free"
        ("$testcase")
        : "+++ $testcase END +++"
    done
}
