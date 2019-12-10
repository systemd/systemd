#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test ExecXYZEx= service unit dbus hookups"
. $TEST_BASE_DIR/test-functions

do_test "$@" 40
