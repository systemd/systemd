#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Inspired by https://github.com/systemd/systemd/issues/9508
set -eux
set -o pipefail

test_snippet() {
    # First call with --dry-run to test the code paths
    systemd-tmpfiles --dry-run "$@" - <<EOF
d /var/tmp/foobar-test-06
d /var/tmp/foobar-test-06/important
R /var/tmp/foobar-test-06
EOF

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
test ! -f /var/tmp/foobar-test-06
test ! -f /var/tmp/foobar-test-06/important

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
test ! -f /var/tmp/foobar-test-06/something-else
