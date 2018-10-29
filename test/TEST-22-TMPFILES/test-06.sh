#! /bin/bash
#
# Inspired by https://github.com/systemd/systemd/issues/9508
#

set -e

test_snippet() {
        systemd-tmpfiles "$@" - <<EOF
d /var/tmp/foobar-test-06
d /var/tmp/foobar-test-06/important
R /var/tmp/foobar-test-06
EOF
}

test_snippet --create --remove
test -d /var/tmp/foobar-test-06
test -d /var/tmp/foobar-test-06/important

test_snippet --remove
! test -f /var/tmp/foobar-test-06
! test -f /var/tmp/foobar-test-06/important

test_snippet --create
test -d /var/tmp/foobar-test-06
test -d /var/tmp/foobar-test-06/important

touch /var/tmp/foobar-test-06/something-else

test_snippet --create
test -d /var/tmp/foobar-test-06
test -d /var/tmp/foobar-test-06/important
test -f /var/tmp/foobar-test-06/something-else

test_snippet --create --remove
test -d /var/tmp/foobar-test-06
test -d /var/tmp/foobar-test-06/important
! test -f /var/tmp/foobar-test-06/something-else
