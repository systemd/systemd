#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

echo "foo.bar=42" > /tmp/foo.conf
[[ $(/usr/lib/systemd/systemd-sysctl /tmp/foo.conf)$? -eq 0 ]]
[[ $(/usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf)$? -ne 0 ]]

echo "-foo.foo=42" > /tmp/foo.conf
[[ $(/usr/lib/systemd/systemd-sysctl /tmp/foo.conf)$? -eq 0 ]]
[[ $(/usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf)$? -eq 0 ]]

touch /testok
