#!/bin/bash
set -e
TEST_DESCRIPTION="test unit freezing and thawing via DBus and systemctl"
TEST_NO_NSPAWN=1
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 38
