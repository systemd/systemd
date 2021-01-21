#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test migrating state directory from DynamicUser=1 to DynamicUser=0 and back"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 34
