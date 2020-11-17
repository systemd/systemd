#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test oneshot unit restart on failure"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 41
