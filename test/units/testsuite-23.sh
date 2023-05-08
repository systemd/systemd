#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

declare -i CHILD_PID=0

# Note: all the signal shenanigans are necessary for the Upholds= tests

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

    while kill -0 "$pid"; do
        wait "$pid" || :
    done

    wait "$pid"
}

trap_with_sig handle_signal SIGUSR1 SIGUSR2 SIGRTMIN+1

for script in "${0%.sh}".*.sh; do
    echo "Running $script"
    "./$script" &
    CHILD_PID=$!
    wait_harder "$CHILD_PID"
done

touch /testok
rm /failed
