#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# meson test wrapper that replays crashing tests under gdb and prints a
# backtrace, so SIGSEGV/SIGABRT/etc. failures in CI show a stack trace inline
# in the test log instead of just an exit code.
#
# Usage: meson test --wrapper=$PWD/tools/test-crash-trace.sh

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

rc=0
"$@" || rc=$?

# Replay only on actual crash signals (128 + signal).
# SIGTERM/SIGKILL/SIGPIPE/SIGALRM mean the test was killed by the environment
# (timeout, etc.), and not that it really crashed, so it is not useful to
# replay it under gdb.
case "$rc" in
    $((128 + $(kill -l ILL)))|$((128 + $(kill -l ABRT)))|$((128 + $(kill -l BUS)))|$((128 + $(kill -l FPE)))|$((128 + $(kill -l SEGV))))
        if command -v gdb >/dev/null 2>&1; then
            echo "===== exit $rc — replaying under gdb =====" >&2
            style_args=()
            if [[ -t 2 ]]; then
                style_args=(--ex 'set style enabled on')
            fi
            gdb --batch \
                --ex 'set pagination off' \
                ${style_args[@]+"${style_args[@]}"} \
                --ex 'run' \
                --ex 'thread apply all bt full' \
                --args "$@" >&2 || true
        else
            echo "===== exit $rc — install gdb for a backtrace =====" >&2
        fi
        ;;
esac

# If the child died by signal, re-raise it so the parent's wait() observes
# WIFSIGNALED instead of a plain exit code. Best-effort: SIGKILL can't be
# delivered to ourselves and would have killed us already.
if [[ $rc -gt 128 ]]; then
    sig=$((rc - 128))
    trap - "$sig" 2>/dev/null || true
    # Suppress the wrapper bash's own core dump from the re-raised crash signal;
    # the original test binary already had its chance to dump core on line 18.
    ulimit -c 0
    kill -s "$sig" $$ 2>/dev/null || true
fi

exit "$rc"
