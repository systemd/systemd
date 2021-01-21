#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test ExecCondition= does not restart on abnormal or failure"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 51
