#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Utility functions for shell tests

assert_true() {(
    set +ex

    local rc

    "$@"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "FAIL: command '$*' failed with exit code $rc" >&2
        exit 1
    fi
)}


assert_eq() {(
    set +ex

    if [[ "${1?}" != "${2?}" ]]; then
        echo "FAIL: expected: '$2' actual: '$1'" >&2
        exit 1
    fi
)}

assert_in() {(
    set +ex

    if ! [[ "${2?}" =~ ${1?} ]]; then
        echo "FAIL: '$1' not found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_not_in() {(
    set +ex

    if [[ "${2?}" =~ ${1?} ]]; then
        echo "FAIL: '$1' found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_rc() {(
    set +ex

    local rc exp="${1?}"

    shift
    "$@"
    rc=$?
    assert_eq "$rc" "$exp"
)}
