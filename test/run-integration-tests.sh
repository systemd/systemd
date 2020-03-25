#!/usr/bin/env bash
set -e

BUILD_DIR="$($(dirname "$0")/../tools/find-build-dir.sh)"
if [ $# -gt 0 ]; then
    args="$@"
    do_clean=0
else
    args="setup run clean-again"
    do_clean=1
fi

ninja -C "$BUILD_DIR"

declare -A results

COUNT=0
FAILURES=0

cd "$(dirname "$0")"

if [ $do_clean = 1 ]; then
    for TEST in TEST-??-* ; do
        ( set -x ; make -C "$TEST" "BUILD_DIR=$BUILD_DIR" clean )
    done
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

    echo -e "\n--x-- Running $TEST --x--"
    set +e
    ( set -x ; make -C "$TEST" "BUILD_DIR=$BUILD_DIR" $args )
    RESULT=$?
    set -e
    echo "--x-- Result of $TEST: $RESULT --x--"

    results["$TEST"]="$RESULT"

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
    if [ "$RESULT" -eq "0" ] ; then
        echo "$TEST: SUCCESS"
    else
        echo "$TEST: FAIL"
    fi
done | sort

if [ "$FAILURES" -eq 0 ] ; then
    echo -e "\nALL $COUNT TESTS PASSED"
else
    echo -e "\nTOTAL FAILURES: $FAILURES OF $COUNT"
fi

exit "$FAILURES"
