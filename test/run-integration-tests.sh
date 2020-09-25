#!/usr/bin/env bash
set -e

BUILD_DIR="$($(dirname "$0")/../tools/find-build-dir.sh)"
if [ $# -gt 0 ]; then
    args="$@"
else
    args="setup run clean-again"
fi
args_no_clean=$(sed -r 's/\bclean\b//g' <<<$args)
do_clean=$( [ "$args" = "$args_no_clean" ]; echo $? )

ninja -C "$BUILD_DIR"

declare -A results
declare -A times

COUNT=0
FAILURES=0

cd "$(dirname "$0")"

# Let's always do the cleaning operation first, because it destroys the image
# cache.
if [ $do_clean = 1 ]; then
    for TEST in TEST-??-* ; do
        ( set -x ; make -C "$TEST" "BUILD_DIR=$BUILD_DIR" clean )
    done

    [ -n "$args_no_clean" ] || exit 0
fi

pass_blacklist() {
    for marker in $BLACKLIST_MARKERS; do
        if [ -f "$1/$marker" ]; then
            echo "========== BLACKLISTED: $1 ($marker) =========="
            return 1
        fi
    done
    return 0
}

for TEST in TEST-??-* ; do
    COUNT=$(($COUNT+1))

    pass_blacklist $TEST || continue
    start=$(date +%s)

    echo -e "\n--x-- Running $TEST --x--"
    set +e
    ( set -x ; make -C "$TEST" "BUILD_DIR=$BUILD_DIR" $args_no_clean )
    RESULT=$?
    set -e
    echo "--x-- Result of $TEST: $RESULT --x--"

    results["$TEST"]="$RESULT"
    times["$TEST"]=$(( $(date +%s) - $start ))

    [ "$RESULT" -ne "0" ] && FAILURES=$(($FAILURES+1))
done

if [ $FAILURES -eq 0 -a $do_clean = 1 ]; then
    for TEST in ${!results[@]}; do
        ( set -x ; make -C "$TEST" "BUILD_DIR=$BUILD_DIR" clean-again )
    done
fi

echo ""

for TEST in ${!results[@]}; do
    RESULT="${results[$TEST]}"
    time="${times[$TEST]}"
    string=$([ "$RESULT" = "0" ] && echo "SUCCESS" || echo "FAIL")
    printf "%-35s %-8s (%3s s)\n" "${TEST}:" "${string}" "$time"
done | sort

if [ "$FAILURES" -eq 0 ] ; then
    echo -e "\nALL $COUNT TESTS PASSED"
else
    echo -e "\nTOTAL FAILURES: $FAILURES OF $COUNT"
fi

exit "$FAILURES"
