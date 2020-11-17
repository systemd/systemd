#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="FailureAction= operation"

. $(dirname ${BASH_SOURCE[0]})/../test-functions
QEMU_TIMEOUT=600

do_test "$@" 18
