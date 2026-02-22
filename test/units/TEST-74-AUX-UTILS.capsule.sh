#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! check_nss_module systemd; then
    exit 0
fi

at_exit() {
    set +e
    systemctl --no-block stop capsule@foobar.service
    rm -rf /run/capsules/foobar
    rm -rf /var/lib/capsules/foobar
    rm -f /run/systemd/system/capsule@.service.d/99-asan.conf
}

trap at_exit EXIT

# Appease ASan, since the capsule@.service uses DynamicUser=yes
systemctl edit --runtime --stdin capsule@.service --drop-in=99-asan.conf <<EOF
[Service]
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
EOF

(! test -f /run/capsules/foobar )
(! test -f /var/lib/capsules/foobar )
(! id -u c-foobar )

systemctl start capsule@foobar.service

test -d /run/capsules/foobar
test -d /var/lib/capsules/foobar
id -u c-foobar

systemctl status capsule@foobar.service

busctl -C foobar

systemctl -C foobar

systemd-run -C foobar -u sleepinfinity sleep infinity

systemctl -C foobar status sleepinfinity

systemctl -C foobar stop sleepinfinity

(! systemctl clean capsule@foobar.service )

systemctl stop capsule@foobar.service

systemctl clean capsule@foobar.service --what=all

(! test -f /run/capsules/foobar )
(! test -f /var/lib/capsules/foobar )
(! id -u c-foobar )
