#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

systemd-analyze log-level debug

systemd-run --wait -p LogNamespace=foobar echo "hello world"

journalctl --namespace=foobar --sync
journalctl -o cat --namespace=foobar >/tmp/hello-world
journalctl -o cat >/tmp/no-hello-world

grep "^hello world$" /tmp/hello-world
(! grep "^hello world$" /tmp/no-hello-world)

systemd-analyze log-level info

echo OK >/testok

exit 0
