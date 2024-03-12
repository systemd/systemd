#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

is_valid_target() {
    local target="${1:?}"
    local t

    for t in all setup run clean clean-again; do
        [[ "$target" == "$t" ]] && return 0
    done

    return 1
}

pass_deny_list() {
    local test="${1:?}"
    local marker

    for marker in $DENY_LIST_MARKERS $BLACKLIST_MARKERS; do
        if [[ -f "$test/$marker" ]]; then
            echo "========== DENY-LISTED: $test ($marker) =========="
            return 1
        fi
    done

    return 0
}

test_run() {
    local test_name="${1:?}"
    shift

    if [[ $# -eq 0 ]]; then
        echo >&2 "test_run: missing arguments"
        exit 1
    fi

    # Note: let's be very explicit in reporting the return code of the test command here, i.e don't rely on
    #       `set -e` or the return code of the last statement in the function, since reporting false positive
    #       would be very bad in this case.
    if [[ "${SPLIT_TEST_LOGS:-0}" -ne 0 && -n "${ARTIFACT_DIRECTORY:-}" ]]; then
        (set -x; "$@") &>>"$ARTIFACT_DIRECTORY/$test_name.log" || return $?
    else
        (set -x; "$@") || return $?
    fi
}

ARGS=(setup run clean-again)
CLEAN=0
CLEAN_AGAIN=0
COUNT=0
FAILURES=0
declare -A RESULTS
declare -A TIMES

if [[ "${NO_BUILD:-0}" =~ ^(1|yes|true)$ ]]; then
    BUILD_DIR=""
elif BUILD_DIR="$("$(dirname "$0")/../tools/find-build-dir.sh")"; then
    ninja -C "$BUILD_DIR"
else
    echo >&2 "No build found, please set BUILD_DIR or NO_BUILD"
    exit 1
fi

if [[ $# -gt 0 ]]; then
    ARGS=("$@")
fi

# Reject invalid make targets
for arg in "${ARGS[@]}"; do
    if ! is_valid_target "$arg"; then
        echo >&2 "Invalid target: $arg"
        exit 1
    fi
done

# Separate 'clean' and 'clean-again' operations
args_filtered=()
for arg in "${ARGS[@]}"; do
    if [[ "$arg" == "clean-again" ]]; then
        CLEAN_AGAIN=1
    elif [[ "$arg" == "clean" ]]; then
        CLEAN=1
    else
        args_filtered+=("$arg")
    fi
done
ARGS=("${args_filtered[@]}")

cd "$(dirname "$0")"

SELECTED_TESTS="${SELECTED_TESTS:-TEST-??-*}"

# Let's always do the cleaning operation first, because it destroys the image
# cache.
if [[ $CLEAN -eq 1 ]]; then
    for test in $SELECTED_TESTS; do
        test_run "$test" make -C "$test" clean
    done
fi

# Run actual tests (if requested)
if [[ ${#ARGS[@]} -ne 0 ]]; then
    for test in $SELECTED_TESTS; do
        COUNT=$((COUNT + 1))

        pass_deny_list "$test" || continue
        SECONDS=0

        echo -e "\n[$(date +%R:%S)] --x-- Running $test --x--"
        set +e
        test_run "$test" make -C "$test" "${ARGS[@]}"
        result=$?
        set -e
        echo "[$(date +%R:%S)] --x-- Result of $test: $result --x--"

        RESULTS["$test"]="$result"
        TIMES["$test"]="$SECONDS"

        [[ "$result" -ne 0 ]] && FAILURES=$((FAILURES + 1))
    done
fi

# Run clean-again, if requested, and if no tests failed
if [[ $FAILURES -eq 0 && $CLEAN_AGAIN -eq 1 ]]; then
    for test in "${!RESULTS[@]}"; do
        test_run "$test" make -C "$test" clean-again
    done
fi

echo ""

for test in "${!RESULTS[@]}"; do
    result="${RESULTS[$test]}"
    time="${TIMES[$test]}"
    [[ "$result" -eq 0 ]] && string="SUCCESS" || string="FAIL"
    printf "%-35s %-8s (%3s s)\n" "$test:" "$string" "$time"
done | sort

if [[ "$FAILURES" -eq 0 ]]; then
    echo -e "\nALL $COUNT TESTS PASSED"
else
    echo -e "\nTOTAL FAILURES: $FAILURES OF $COUNT"
fi

# If we have coverage files, merge them into a single report for upload
if [[ -n "$ARTIFACT_DIRECTORY" ]]; then
    lcov_args=()

    while read -r info_file; do
        lcov_args+=(--add-tracefile "$info_file")
    done < <(find "$ARTIFACT_DIRECTORY" -maxdepth 1 -name "*.coverage-info")

    if [[ ${#lcov_args[@]} -gt 1 ]]; then
        lcov "${lcov_args[@]}" --output-file "$ARTIFACT_DIRECTORY/merged.coverage-info"
    fi
fi

exit "$FAILURES"
