#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

export SYSTEMD_LOG_LEVEL=debug

echo "foo.bar=42" > /tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl /tmp/foo.conf
assert_rc 1 /usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf

echo "-foo.foo=42" > /tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl /tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf

touch /testok
