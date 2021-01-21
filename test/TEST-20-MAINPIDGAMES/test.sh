#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test changing main PID"

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 20
