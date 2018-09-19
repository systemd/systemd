#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
#set -ex
#set -o pipefail

for i in /usr/lib/systemd/tests/test-*; do
    if [[ ! -x $i ]]; then continue; fi
    NAME=${i##*/}
    echo "Running $NAME"
    $i > /$NAME.log 2>&1
    ret=$?
    if (( $ret && $ret != 77 )); then
        echo "$NAME failed with $ret"
        echo $NAME >> /failed-tests
        echo "--- $NAME begin ---" >> /failed
        cat /$NAME.log >> /failed
        echo "--- $NAME end ---" >> /failed
    elif (( $ret == 77 )); then
        echo "$NAME skipped"
        echo $NAME >> /skipped-tests
        echo "--- $NAME begin ---" >> /skipped
        cat /$NAME.log >> /skipped
        echo "--- $NAME end ---" >> /skipped
    else
        echo "$NAME OK"
        echo $NAME >> /testok
    fi

    systemd-cat echo "--- $NAME ---"
    systemd-cat cat /$NAME.log
done

exit 0
