#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test that KillMode=mixed does not leave left over processes with ExecStopPost="
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 47
