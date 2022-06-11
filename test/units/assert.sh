#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# utility functions for shell tests

assert_true() {
    local rc

    set +e
    "$@"
    rc=$?
    set -e
    if [[ "$rc" != "0" ]]; then
        echo "FAIL: command '$*' failed with exit code $rc" >&2
        exit 1
    fi
}


assert_eq() {
    if [[ "$1" != "$2" ]]; then
        echo "FAIL: expected: '$2' actual: '$1'" >&2
        exit 1
    fi
}

assert_in() {
    if ! echo "$2" | grep -q "$1"; then
        echo "FAIL: '$1' not found in:" >&2
        echo "$2" >&2
        exit 1
    fi
}

assert_not_in() {
    if echo "$2" | grep -q "$1"; then
        echo "FAIL: '$1' found in:" >&2
        echo "$2" >&2
        exit 1
    fi
}

assert_rc() {
    local exp=$1
    local rc
    shift
    set +e
    "$@"
    rc=$?
    set -e
    assert_eq "$rc" "$exp"
}
