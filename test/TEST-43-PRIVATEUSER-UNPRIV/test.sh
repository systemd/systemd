#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test PrivateUsers=yes on user manager"
. $TEST_BASE_DIR/test-functions

has_user_dbus_socket || exit 0

do_test "$@" 43
