#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

at_exit() {
    set +e
    systemctl --no-block stop capsule@foobar.service
    rm -rf /run/capsules/foobar
    rm -rf /var/lib/capsules/foobar
}

trap at_exit EXIT

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

systemd-run -C foobar -u sleepinfinity /bin/sleep infinity

systemctl -C foobar status sleepinfinity

systemctl -C foobar stop sleepinfinity

(! systemctl clean capsule@foobar.service )

systemctl stop capsule@foobar.service

systemctl clean capsule@foobar.service --what=all

(! test -f /run/capsules/foobar )
(! test -f /var/lib/capsules/foobar )
(! id -u c-foobar )
