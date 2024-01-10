#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

systemd-analyze log-level debug

journalctl --list-namespaces -o json | jq .

systemd-run --wait -p LogNamespace=foobar echo "hello world"
systemd-run --wait -p LogNamespace=foobaz echo "hello world"

journalctl --namespace=foobar --sync
journalctl --namespace=foobaz --sync
ls -l /var/log/journal/
journalctl --list-namespaces

journalctl -o cat --namespace=foobar >/tmp/hello-world
journalctl -o cat >/tmp/no-hello-world

journalctl --list-namespaces | grep foobar
journalctl --list-namespaces | grep foobaz
journalctl --list-namespaces -o json | jq .
[[ "$(journalctl --root=/tmp --list-namespaces --quiet)" == "" ]]

grep "^hello world$" /tmp/hello-world
(! grep "^hello world$" /tmp/no-hello-world)

systemd-analyze log-level info

touch /testok
