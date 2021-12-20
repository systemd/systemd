#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

if [ "$NO_BUILD" ]; then
    BUILD_DIR=""
elif BUILD_DIR="$("$(dirname "$0")/../tools/find-build-dir.sh")"; then
    ninja -C "$BUILD_DIR"
else
    echo "No build found, please set BUILD_DIR or NO_BUILD" >&2
    exit 1
fi

if [ $# -gt 0 ]; then
    args="$*"
else
    args="setup run clean-again"
fi

VALID_TARGETS="all setup run clean clean-again"

is_valid_target() {
    for target in $VALID_TARGETS; do
        [ "$1" = "$target" ] && return 0
    done
    return 1
}

# reject invalid make targets in $args
for arg in $args; do
    if ! is_valid_target "$arg"; then
        echo "Invalid target: $arg" >&2
        exit 1
    fi
done

CLEAN=0
CLEANAGAIN=0

# separate 'clean' and 'clean-again' operations
[[ "$args" =~ "clean-again" ]] && CLEANAGAIN=1
args=${args/clean-again}
[[ "$args" =~ "clean" ]] && CLEAN=1
args=${args/clean}

declare -A results
declare -A times

COUNT=0
COUNT_SUCCESS=0
COUNT_SKIPPED=0
COUNT_FAILURES=0

cd "$(dirname "$0")"

pass_deny_list() {
    for marker in $DENY_LIST_MARKERS $BLACKLIST_MARKERS; do
        if [ -f "$1/$marker" ]; then
            echo "========== DENY-LISTED: $1 ($marker) =========="
            return 1
        fi
    done
    return 0
}

SELECTED_TESTS="${SELECTED_TESTS:-TEST-??-*}"

# Let's always do the cleaning operation first, because it destroys the image
# cache.
if [ $CLEAN = 1 ]; then
    for TEST in $SELECTED_TESTS; do
        ( set -x ; make -C "$TEST" clean )
    done
fi

# Run actual tests (if requested)
if [[ $args =~ [a-z] ]]; then
    for TEST in $SELECTED_TESTS; do
        COUNT=$((COUNT+1))

        pass_deny_list "$TEST" || continue
        start=$(date +%s)

        echo -e "\n[$(date +%R:%S)] --x-- Running $TEST --x--"
        set +e
        # shellcheck disable=SC2086
        ( set -x ; make -C "$TEST" $args )
        RESULT=$?
        set -e
        echo "[$(date +%R:%S)] --x-- Result of $TEST: $RESULT --x--"

        results["$TEST"]="$RESULT"
        times["$TEST"]=$(( $(date +%s) - start ))

        if [[ "$RESULT" -eq "0" ]]; then
            COUNT_SUCCESS=$((COUNT_SUCCESS+1))
        elif [[ "$RESULT" -eq "77" ]]; then
            COUNT_SKIPPED=$((COUNT_SKIPPED+1))
        else
            COUNT_FAILURES=$((COUNT_FAILURES+1))
        fi
    done
fi

# Run clean-again, if requested, and if no tests failed
if [[ $COUNT_FAILURES -eq 0 && $CLEANAGAIN -eq 1 ]]; then
    for TEST in "${!results[@]}"; do
        ( set -x ; make -C "$TEST" clean-again )
    done
fi

echo ""

for TEST in "${!results[@]}"; do
    RESULT="${results[$TEST]}"
    time="${times[$TEST]}"
    if [[ "$RESULT" -eq "0" ]]; then
        string="SUCCESS"
    elif [[ "$RESULT" -eq "77" ]]; then
        string="SKIPPED"
    else
        string="FAIL"
    fi
    printf "%-35s %-8s (%3s s)\n" "${TEST}:" "${string}" "$time"
done | sort

echo -e "\nTOTAL: $COUNT, SUCCESS: $COUNT_SUCCESS, SKIPPED: $COUNT_SKIPPED, FAILURES: $COUNT_FAILURES"

# If we have coverage files, merge them into a single report for upload
if [ -n "${ARTIFACT_DIRECTORY}" ]; then
    lcov_args=()

    while read -r info_file; do
        lcov_args+=(--add-tracefile "${info_file}")
    done < <(find "${ARTIFACT_DIRECTORY}" -maxdepth 1 -name "*.coverage-info")

    if [ ${#lcov_args[@]} -gt 1 ]; then
        lcov "${lcov_args[@]}" --output-file "${ARTIFACT_DIRECTORY}/merged.coverage-info"
    fi
fi

exit "$COUNT_FAILURES"
