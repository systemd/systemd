#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Ensure %j Wants directives work"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

. $(dirname ${BASH_SOURCE[0]})/../test-functions

do_test "$@" 28
