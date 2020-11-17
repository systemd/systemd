#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Journal-related tests"

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 04
