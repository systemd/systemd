# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

declare -i _CHILD_PID=0
_PASSED_TESTS=()
_SKIPPED_TESTS=()
# Excluded by the operator rather than skipped by themselves. Both filters are unanchored
# regexes: an unmatched TEST_MATCH_SUBTEST is most likely a typo (asked for something, got
# nothing), while a TEST_SKIP_SUBTESTS hit is an explicit removal -- but a skip broad enough to
# empty the whole run is refused in _show_summary unless the parent ran testcases of its own,
# or a finalizing runner is about to turn it into a proper skip.
_UNMATCHED_TESTS=()
_EXCLUDED_TESTS=()
declare -i _EXECUTED_TESTCASES=0
declare -i _WILL_FINALIZE=0

# A subtest may exit with this code to report that it skipped itself,
# matching the skip code used by the integration test harness.
_SUBTEST_SKIP_RC=77

# The subtests of the current test script. Without nullglob an unmatched pattern stays in the
# array verbatim, so emptiness is "does the first element exist", never "is the array empty" --
# one helper, so no two call sites can answer that differently. Prints the list, fails when
# there is none.
_list_subtests() {
    local subtests=("${0%.sh}".*.sh)

    [[ -e "${subtests[0]}" ]] || return 1
    printf '%s\n' "${subtests[@]}"
}

# Applies the subtest filters and records what they removed; returns 0 when the subtest is
# filtered out, so the caller skips it. One place owns this accounting: the _show_summary guards
# read these arrays to refuse a run that executed nothing, so the two runners must count
# identically.
_subtest_filtered_out() {
    local subtest="${1:?}"
    local skips=() skip

    if [[ -n "${TEST_MATCH_SUBTEST:-}" ]] && ! [[ "$subtest" =~ $TEST_MATCH_SUBTEST ]]; then
        echo "Skipping $subtest (not matching '$TEST_MATCH_SUBTEST')"
        _UNMATCHED_TESTS+=("$subtest")
        return 0
    fi

    # read -ra rather than an unquoted expansion: the words are EREs, and several legitimate
    # ones (a trailing *, a bracket class) are also globs the shell would otherwise replace
    # with matching filenames.
    read -ra skips <<< "${TEST_SKIP_SUBTESTS:-}"
    for skip in "${skips[@]}"; do
        if [[ "$subtest" =~ $skip ]]; then
            echo "Skipping $subtest (matching '$skip')"
            _EXCLUDED_TESTS+=("$subtest")
            return 0
        fi
    done

    return 1
}

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

    # An empty subtest run is refused only when the whole process ran nothing: a parent that
    # executed testcases of its own may see a foreign TEST_MATCH_SUBTEST, an explicit skip-all,
    # or simply no matching subtests, and its summary stands on those testcases. This reads
    # $_EXECUTED_TESTCASES, so a parent with both phases must call run_testcases before
    # run_subtests (as TEST-89 does).
    if [[ ${#_PASSED_TESTS[@]} -eq 0 && ${#_SKIPPED_TESTS[@]} -eq 0 && $_EXECUTED_TESTCASES -eq 0 ]]; then
        # The filters reach every guest, so a filter that removed everything here may simply
        # be aimed at another test -- the same reasoning as run_testcases' empty-run arm, and
        # the same verdict: a skip, visible either way, red never, green no-op never.
        if [[ ${#_UNMATCHED_TESTS[@]} -gt 0 && ${#_EXCLUDED_TESTS[@]} -eq 0 ]]; then
            echo "TEST_MATCH_SUBTEST='${TEST_MATCH_SUBTEST:-}' matched no subtest" | tee --append /skipped
            exit "$_SUBTEST_SKIP_RC"
        fi

        if [[ ${#_EXCLUDED_TESTS[@]} -eq 0 ]]; then
            echo >&2 "No tests were executed, this is most likely an error"
            exit 1
        fi

        # Everything the filter left was named by TEST_SKIP_SUBTESTS. When a finalizing
        # runner follows, let it report the empty run with its own summary; otherwise skip
        # here directly.
        if [[ $_WILL_FINALIZE -eq 0 ]]; then
            local also=""
            [[ ${#_UNMATCHED_TESTS[@]} -gt 0 ]] && also=" (and TEST_MATCH_SUBTEST='${TEST_MATCH_SUBTEST:-}')"
            echo "TEST_SKIP_SUBTESTS='${TEST_SKIP_SUBTESTS:-}'$also filtered out every subtest" | tee --append /skipped
            exit "$_SUBTEST_SKIP_RC"
        fi
    fi

    if [[ ${#_UNMATCHED_TESTS[@]} -gt 0 || ${#_EXCLUDED_TESTS[@]} -gt 0 ]]; then
        printf "FILTERED OUT: %3d:\n" "$((${#_UNMATCHED_TESTS[@]} + ${#_EXCLUDED_TESTS[@]}))"
        printf "        %s\n" "${_UNMATCHED_TESTS[@]}" "${_EXCLUDED_TESTS[@]}"
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
    local subtests=()
    local subtest rc

    mapfile -t subtests < <(_list_subtests)

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
        if _subtest_filtered_out "$subtest"; then
            continue
        fi

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
    local subtests=()
    local subtest rc

    mapfile -t subtests < <(_list_subtests)

    if [[ "${#subtests[@]}" -eq 0 ]]; then
        echo >&2 "No subtests found for file $0"
        exit 1
    fi

    for subtest in "${subtests[@]}"; do
        if _subtest_filtered_out "$subtest"; then
            continue
        fi

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
    # _show_summary has already errored out on a run that executed nothing it should have; what is
    # left here is a deliberate TEST_SKIP_SUBTESTS covering everything, which reports as a skip.
    if [[ ${#_PASSED_TESTS[@]} -eq 0 && ${#_SKIPPED_TESTS[@]} -eq 0 && ${#_EXCLUDED_TESTS[@]} -gt 0 ]]; then
        echo "All subtests filtered out" | tee --append /skipped
        exit "$_SUBTEST_SKIP_RC"
    fi

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
    _WILL_FINALIZE=1
    run_subtests
    _finalize_subtests
}

# Like run_subtests_and_exit, but propagates the given signals to the subtests (see
# run_subtests_with_signals).
run_subtests_with_signals_and_exit() {
    _WILL_FINALIZE=1
    run_subtests_with_signals "$@"
    _finalize_subtests
}

# Run all test cases (i.e. functions prefixed with testcase_ in the current namespace)
run_testcases() {
    local testcase testcases skip skips=()

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

        read -ra skips <<< "${TEST_SKIP_TESTCASES:-}"
        for skip in "${skips[@]}"; do
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
        _EXECUTED_TESTCASES+=1
        : "+++ $testcase END +++"
    done

    # The mirror of _show_summary's refusal for subtests, reachable since the wrapper forwards
    # the testcase filters into every guest: a run in which the filters removed every testcase
    # must not walk on to /testok as a green no-op. It cannot be a hard failure either -- the
    # filters reach every test and every subtest process, so an all-excluding filter here may
    # simply be aimed at another test (or at this parent's subtest phase). When this file has
    # subtests, let the run carry on to them and their accounting decide; when this process was
    # the whole run, report a skip: visible either way, red never.
    if [[ $_EXECUTED_TESTCASES -eq 0 && ( -n "${TEST_MATCH_TESTCASE:-}" || -n "${TEST_SKIP_TESTCASES:-}" ) ]]; then
        # A positive selector that matched nothing means this process has nothing to do --
        # skip even when subtests follow, since running those anyway would green-stamp a run
        # in which the requested testcase never executed. An all-excluding skip list, by
        # contrast, is a deliberate exclusion: carry on to the subtests when there are any.
        # (No /skipped write here: that file asserts the whole test skipped, and this may be
        # one subtest process among many.)
        if [[ -n "${TEST_MATCH_TESTCASE:-}" ]]; then
            echo "TEST_MATCH_TESTCASE='$TEST_MATCH_TESTCASE' matched no testcase; skipping"
            exit "$_SUBTEST_SKIP_RC"
        fi
        if _list_subtests >/dev/null; then
            echo "All testcases filtered out; continuing to this test's subtests"
        else
            echo "All testcases filtered out; skipping"
            exit "$_SUBTEST_SKIP_RC"
        fi
    fi
}
