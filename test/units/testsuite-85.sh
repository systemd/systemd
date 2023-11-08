#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

(! test -f /run/projects/foobar )
(! test -f /var/lib/projects/foobar )
(! id -u p_foobar )

systemctl start project@foobar.service

test -d /run/projects/foobar
test -d /var/lib/projects/foobar
id -u p_foobar

systemctl status project@foobar.service

busctl -J foobar

systemctl -J foobar

systemd-run -J foobar -u sleepinfinity /bin/sleep infinity

systemctl -J foobar status sleepinfinity

systemctl -J foobar stop sleepinfinity

(! systemctl clean project@foobar.service )

systemctl stop project@foobar.service

systemctl clean project@foobar.service --what=all

(! test -f /run/projects/foobar )
(! test -f /var/lib/projects/foobar )
(! id -u p_foobar )

touch /testok
