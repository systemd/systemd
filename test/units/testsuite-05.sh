#!/usr/bin/env bash
set -x
set -e
set -o pipefail

P=/run/systemd/system.conf.d
mkdir $P

cat >$P/rlimits.conf <<EOF
[Manager]
DefaultLimitNOFILE=10000:16384
EOF

systemctl daemon-reload

[[ "$(systemctl show --value -p DefaultLimitNOFILESoft)" = "10000" ]]
[[ "$(systemctl show --value -p DefaultLimitNOFILE)" = "16384" ]]

[[ "$(systemctl show --value -p LimitNOFILESoft testsuite-05.service)" = "10000" ]]
[[ "$(systemctl show --value -p LimitNOFILE testsuite-05.service)" = "16384" ]]

systemd-run --wait -t bash -c '[[ "$(ulimit -n -S)" = "10000" ]]'
systemd-run --wait -t bash -c '[[ "$(ulimit -n -H)" = "16384" ]]'

touch /testok
