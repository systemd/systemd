#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

P=/run/systemd/system.conf.d
mkdir $P

cat >$P/rlimits.conf <<EOF
[Manager]
DefaultLimitNOFILE=10000:16384
EOF

systemctl daemon-reload

[[ "$(systemctl show -P DefaultLimitNOFILESoft)" = "10000" ]]
[[ "$(systemctl show -P DefaultLimitNOFILE)" = "16384" ]]

[[ "$(systemctl show -P LimitNOFILESoft testsuite-05.service)" = "10000" ]]
[[ "$(systemctl show -P LimitNOFILE testsuite-05.service)" = "16384" ]]

# shellcheck disable=SC2016
systemd-run --wait -t bash -c '[[ "$(ulimit -n -S)" = "10000" ]]'
# shellcheck disable=SC2016
systemd-run --wait -t bash -c '[[ "$(ulimit -n -H)" = "16384" ]]'

touch /testok
