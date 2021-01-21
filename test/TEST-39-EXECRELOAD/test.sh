#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test ExecReload= (PR #13098)"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 39
