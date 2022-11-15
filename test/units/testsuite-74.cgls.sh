#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-cgls
systemd-cgls --all --full
systemd-cgls -k
systemd-cgls --xattr=yes
systemd-cgls --xattr=no
systemd-cgls --cgroup-id=yes
systemd-cgls --cgroup-id=no

systemd-cgls /system.slice/systemd-journald.service
systemd-cgls /system.slice/systemd-journald.service /init.scope
systemd-cgls /sys/fs/cgroup/system.slice/systemd-journald.service /init.scope
(cd /sys/fs/cgroup/init.scope && systemd-cgls)
systemd-cgls --unit=systemd-journald.service
# There's most likely no user session running, so we need to create one
systemd-run --user --wait --pipe -M testuser@.host systemd-cgls --user-unit=app.slice

(! systemd-cgls /foo/bar)
(! systemd-cgls --unit=hello.world)
(! systemd-cgls --user-unit=hello.world)
(! systemd-cgls --xattr=foo)
(! systemd-cgls --cgroup-id=foo)
