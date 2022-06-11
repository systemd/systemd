#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# utility functions for shell tests

assert_true() {(
    local rc

    set +ex

    "$@"
    rc=$?
    if [[ "$rc" != "0" ]]; then
        echo "FAIL: command '$*' failed with exit code $rc" >&2
        exit 1
    fi
)}


assert_eq() {(
    set +ex

    if [[ "$1" != "$2" ]]; then
        echo "FAIL: expected: '$2' actual: '$1'" >&2
        exit 1
    fi
)}

assert_in() {(
    set +ex

    if ! [[ "$2" =~ "$1" ]]; then
        echo "FAIL: '$1' not found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_not_in() {(
    set +ex

    if [[ "$2" =~ "$1" ]]; then
        echo "FAIL: '$1' found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_rc() {(
    local rc exp=$1

    set +ex

    shift
    "$@"
    rc=$?
    assert_eq "$rc" "$exp"
)}
