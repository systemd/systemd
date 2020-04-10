#!/bin/bash
set -e
. $TEST_BASE_DIR/test-functions
TEST_REQUIRE_INSTALL_TESTS=0
TEST_DESCRIPTION="testing honor first shutdown"
#INTERACTIVE_DEBUG=1
TEST_NO_QEMU=1

#Using timeout because if the test fails it can loop.
# The reason is because the poweroff executed by end.service
# could turn into a reboot if the test fails.
NSPAWN_TIMEOUT=20

#Remove this file if it exists. this is used along with
# the make target "finish". Since concrete confirmaion is
# only found from the console during the poweroff.
rm -f /tmp/honorfirstshutdown.log >/dev/null

do_test "$@" 52 > /tmp/honorfirstshutdown.log
