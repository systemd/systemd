#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    loginctl disable-linger testuser ||:
    run0 -u testuser systemctl --user stop subgroup-test.service ||:
}

trap at_exit EXIT

loginctl enable-linger testuser
run0 -u testuser systemd-run --user --unit=subgroup-test.service sleep infinity

systemctl kill user@"$(id -u testuser)".service --kill-subgroup=waldo
systemctl kill user@"$(id -u testuser)".service --kill-subgroup=/waldo
systemctl kill user@"$(id -u testuser)".service --kill-subgroup=waldo/knurz
systemctl kill user@"$(id -u testuser)".service --kill-subgroup=/waldo/knurz

(! systemctl kill user@"$(id -u testuser)".service --kill-subgroup=waldo --kill-whom=cgroup-fail)
(! systemctl kill user@"$(id -u testuser)".service --kill-subgroup=/waldo --kill-whom=cgroup-fail)
(! systemctl kill user@"$(id -u testuser)".service --kill-subgroup=waldo/knurz --kill-whom=cgroup-fail)
(! systemctl kill user@"$(id -u testuser)".service --kill-subgroup=/waldo/knurz --kill-whom=cgroup-fail)

run0 -u testuser systemctl --user is-active subgroup-test.service
(! systemctl kill user@"$(id -u testuser)".service --kill-subgroup=app.slice/subgroup-test.service/waldo --kill-whom=cgroup-fail)
run0 -u testuser systemctl --user is-active subgroup-test.service
systemctl kill user@"$(id -u testuser)".service --kill-subgroup=app.slice/subgroup-test.service/waldo
run0 -u testuser systemctl --user is-active subgroup-test.service
systemctl kill user@"$(id -u testuser)".service --kill-subgroup=app.slice/subgroup-test.service --kill-whom=cgroup-fail

timeout 60 bash -c 'while run0 -u testuser systemctl --user is-active subgroup-test.service; do sleep 1; done'
