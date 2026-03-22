#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Just a smoke test for the introspection code
for i in systemd-dissect systemd-id128 systemd-notify; do
    $i --introspect-cli | jq
    $i --intro | grep -e --help
done
