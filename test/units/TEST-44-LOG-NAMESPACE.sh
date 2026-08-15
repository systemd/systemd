#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

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

root="$(mktemp -d /tmp/journal-ns-root.XXXXXX)"
mkdir -p "$root/etc" "$root/var/log/journal/11111111111111111111111111111111.testns"
printf '11111111111111111111111111111111\n' >"$root/etc/machine-id"
[[ "$(journalctl --root="$root" --list-namespaces --quiet)" == "testns" ]]

grep "^hello world$" /tmp/hello-world
(! grep "^hello world$" /tmp/no-hello-world)

touch /testok
