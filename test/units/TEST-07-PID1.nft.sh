#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v nft >/dev/null; then
    echo "nftables is not installed. Skipped NFTSet= tests."
    exit 0
fi

RUN_OUT="$(mktemp)"

run() {
    "$@" |& tee "$RUN_OUT"
}

nft add table inet sd_test
nft add set inet sd_test c '{ type cgroupsv2; }'
nft add set inet sd_test u '{ typeof meta skuid; }'
nft add set inet sd_test g '{ typeof meta skgid; }'

# service
systemd-run --unit test-nft.service --service-type=exec -p DynamicUser=yes \
            -p 'NFTSet=cgroup:inet:sd_test:c user:inet:sd_test:u group:inet:sd_test:g' sleep 10000
run nft list set inet sd_test c
grep -qF "test-nft.service" "$RUN_OUT"
uid=$(userdbctl user --json=short test-nft | jq .uid)
run nft list set inet sd_test u
grep -qF "$uid" "$RUN_OUT"
gid=$(userdbctl user --json=short test-nft | jq .gid)
run nft list set inet sd_test g
grep -qF "$gid" "$RUN_OUT"
systemctl stop test-nft.service

# scope
run systemd-run --scope -u test-nft.scope -p 'NFTSet=cgroup:inet:sd_test:c' nft list set inet sd_test c
grep -qF "test-nft.scope" "$RUN_OUT"

mkdir -p /run/systemd/system
# socket
{
    echo "[Socket]"
    echo "ListenStream=12345"
    echo "BindToDevice=lo"
    echo "NFTSet=cgroup:inet:sd_test:c"
} >/run/systemd/system/test-nft.socket
{
    echo "[Service]"
    echo "ExecStart=sleep 10000"
} >/run/systemd/system/test-nft.service
systemctl daemon-reload
systemctl start test-nft.socket
systemctl status test-nft.socket
run nft list set inet sd_test c
grep -qF "test-nft.socket" "$RUN_OUT"
systemctl stop test-nft.socket
rm -f /run/systemd/system/test-nft.{socket,service}

# slice
mkdir /run/systemd/system/system.slice.d
{
    echo "[Slice]"
    echo "NFTSet=cgroup:inet:sd_test:c"
} >/run/systemd/system/system.slice.d/00-test-nft.conf
systemctl daemon-reload
run nft list set inet sd_test c
grep -qF "system.slice" "$RUN_OUT"
rm -rf /run/systemd/system/system.slice.d

nft flush ruleset
exit 0
