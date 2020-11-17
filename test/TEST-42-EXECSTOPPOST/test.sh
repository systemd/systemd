#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test that ExecStopPost= is always run"

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 42
