#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Resource limits-related tests"

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 05
