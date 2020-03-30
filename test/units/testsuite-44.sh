#!/usr/bin/env bash
set -ex

systemd-analyze log-level debug

systemd-run -p LogNamespace=foobar echo "hello world"

journalctl --namespace=foobar --sync
journalctl --namespace=foobar > /tmp/hello-world
journalctl > /tmp/no-hello-world

grep "hello world" /tmp/hello-world
! grep "hello world" /tmp/no-hello-world

systemd-analyze log-level info

echo OK > /testok

exit 0
