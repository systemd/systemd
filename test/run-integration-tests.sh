#!/bin/bash -e

if ! test -d ../build ; then
        echo "Expected build directory in ../build, but couldn't find it." >&2
        exit 1
fi

ninja -C ../build

declare -A results

RESULT=0
FAILURES=0

for TEST in TEST-??-* ; do
        echo -e "\n--x-- Starting $TEST --x--"
        set +e
        make -C "$TEST" BUILD_DIR=$(pwd)/../build clean setup run
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
        echo -e "\nALL PASSED"
else
        echo -e "\nTOTAL FAILURES: $FAILURES"
fi

exit "$FAILURES"
