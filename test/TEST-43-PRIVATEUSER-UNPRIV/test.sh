#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test PrivateUsers=yes on user manager"
. $(dirname ${BASH_SOURCE[0]})/../test-functions

has_user_dbus_socket || exit 0

do_test "$@" 43
