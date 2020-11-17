#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test adding new BindPaths while unit is already running"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 57
