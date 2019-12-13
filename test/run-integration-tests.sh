#!/bin/bash -e

BUILD_DIR="$($(dirname "$0")/../tools/find-build-dir.sh)"
if [ $# -gt 0 ]; then
    args="$@"
else
    args="clean setup run clean-again"
fi

ninja -C "$BUILD_DIR"

declare -A results

COUNT=0
FAILURES=0

cd "$(dirname "$0")"
for TEST in TEST-??-* ; do
    COUNT=$(($COUNT+1))

    echo -e "\n--x-- Running $TEST --x--"
    set +e
    ( set -x ; make -C "$TEST" "BUILD_DIR=$BUILD_DIR" $args )
    RESULT=$?
    set -e
    echo "--x-- Result of $TEST: $RESULT --x--"

    results["$TEST"]="$RESULT"

    [ "$RESULT" -ne "0" ] && FAILURES=$(($FAILURES+1))
done

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
