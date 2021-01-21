#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test ExecXYZEx= service unit dbus hookups"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 40
