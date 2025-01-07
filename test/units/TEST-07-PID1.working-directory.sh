#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

(! systemd-run --wait -p DynamicUser=yes \
                      -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
                      -p WorkingDirectory='~' true)

assert_eq "$(systemd-run --pipe --uid=root -p WorkingDirectory='~' pwd)" "/root"
assert_eq "$(systemd-run --pipe --uid=nobody -p WorkingDirectory='~' pwd)" "/"
assert_eq "$(systemd-run --pipe --uid=testuser -p WorkingDirectory='~' pwd)" "/home/testuser"

(! systemd-run --wait -p DynamicUser=yes -p User=testuser \
                      -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
                      -p WorkingDirectory='~' true)
