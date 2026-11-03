#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh


if ! test -x /usr/lib/systemd/systemd-imdsd ; then
    echo "No imdsd installed, skipping test."
    exit 77
fi

at_exit() {
    set +e
    systemctl stop fake-imds systemd-imdsd.socket
    # Unmanage the link before removing it, so that networkd also removes its prohibit route and rule
    rm -rf /run/systemd/network/85-imds-early.network /run/systemd/network/85-imds-early.network.d \
           /run/systemd/resolve/static.d/imds-endpoint.rr
    networkctl reload
    ip link del veth-imds
    ip netns del imds
    rm -f /run/credstore/firstboot.hostname /run/credstore/acredtest /run/systemd/system/systemd-imdsd@.service.d/50-env.conf /run/fake-imds-flaky
    rmdir /run/systemd/system/systemd-imdsd@.service.d
    # cached negative entries would short-circuit the /flaky retry on a rerun
    rm -rf /run/systemd/imds/cache/veth-imds
    if [[ -v RP_FILTER_ALL ]]; then
        rm -f /run/sysctl.d/90-imds.conf
        sysctl -w net.ipv4.conf.all.rp_filter="$RP_FILTER_ALL"
    fi
    rm -rf "$WORK_DIR"
}

WORK_DIR="$(mktemp -d)"
trap at_exit EXIT

# Model a cloud instance: IMDS is on another host, behind a veth peer in another network namespace
ip netns add imds
ip link add veth-imds type veth peer name veth-imds-peer netns imds
ip -n imds link set lo up
ip -n imds link set veth-imds-peer up
ip -n imds addr add 192.168.47.1/24 dev veth-imds-peer
ip link set veth-imds up
ip addr add 192.168.47.11/24 dev veth-imds

systemd-run -p Type=notify -p NetworkNamespacePath=/run/netns/imds --unit=fake-imds \
            /usr/lib/systemd/tests/integration-tests/TEST-74-AUX-UTILS/TEST-74-AUX-UTILS.units/fake-imds.py
systemctl status fake-imds

USERDATA='{"systemd.credentials":[{"name":"acredtest","text":"avalue"}]}'

# First try imdsd directly
IMDSD=(/usr/lib/systemd/systemd-imdsd --vendor=test --data-url=http://192.168.47.1:8088 --well-known-key=userdata:/userdata --well-known-key=hostname:/hostname)
assert_eq "$("${IMDSD[@]}" --well-known=hostname)" "piff"
assert_eq "$("${IMDSD[@]}" --well-known=userdata)" "$USERDATA"
assert_eq "$("${IMDSD[@]}" /hostname)" "piff"
assert_eq "$("${IMDSD[@]}" /userdata)" "$USERDATA"

# A request restarted with a new token after 401 still caches its result: a second request must find it in
# the cache, as its data URL is unreachable.
mkdir "$WORK_DIR/runtime"
IMDSD_TOKEN=("${IMDSD[@]}" --interface=veth-imds --token-url=http://192.168.47.1:8088/token --token-header-name=X-Fake-IMDS-Token)
assert_eq "$(RUNTIME_DIRECTORY="$WORK_DIR/runtime" "${IMDSD_TOKEN[@]}" /expiring)" "fresh"
assert_eq "$(RUNTIME_DIRECTORY="$WORK_DIR/runtime" "${IMDSD_TOKEN[@]}" --data-url=http://192.168.47.1:1 /expiring)" "fresh"

# Running out of token refreshes is reported as timeout
(! "${IMDSD_TOKEN[@]}" /unauthorized 2>"$WORK_DIR/unauthorized.err")
cat "$WORK_DIR/unauthorized.err"
grep -F "io.systemd.InstanceMetadata.Timeout" "$WORK_DIR/unauthorized.err" >/dev/null
(! grep -F "Overall timeout reached" "$WORK_DIR/unauthorized.err" >/dev/null)

# Missing keys: both real and fake IMDS answer 404 with a non-empty body
(! "${IMDSD[@]}" /nonexistent 2>"$WORK_DIR/imdsd.err")
cat "$WORK_DIR/imdsd.err"
# expect specific, not generic error
grep -F "io.systemd.InstanceMetadata.KeyNotFound" "$WORK_DIR/imdsd.err" >/dev/null
(! grep -F "io.systemd.System" "$WORK_DIR/imdsd.err" >/dev/null)

# Running out of retries for connection errors is reported as timeout. Slow, as this waits for all retries.
# Same for HTTP 503; run that in parallel to save time. With the token cached above, so that every retry
# reuses it.
(! RUNTIME_DIRECTORY="$WORK_DIR/runtime" "${IMDSD_TOKEN[@]}" /busy 2>"$WORK_DIR/busy.err") &
BUSY_PID=$!
# Retries after a token refresh still back off; also in parallel
(! SYSTEMD_LOG_LEVEL=debug "${IMDSD_TOKEN[@]}" /expiring-busy 2>"$WORK_DIR/expiring-busy.err") &
EXPIRING_BUSY_PID=$!
(! "${IMDSD[@]}" --interface=veth-imds --data-url=http://192.168.47.1:1 /hostname 2>"$WORK_DIR/refused.err")
cat "$WORK_DIR/refused.err"
(! grep -F "Overall timeout reached" "$WORK_DIR/refused.err" >/dev/null)
grep -F "io.systemd.InstanceMetadata.Timeout" "$WORK_DIR/refused.err" >/dev/null
wait "$BUSY_PID"
cat "$WORK_DIR/busy.err"
grep -F "io.systemd.InstanceMetadata.Timeout" "$WORK_DIR/busy.err" >/dev/null
grep -F "Reusing cached token." "$WORK_DIR/busy.err" >/dev/null
# fails right away, does not hang until the overall timeout
(! grep -F "Overall timeout reached" "$WORK_DIR/busy.err" >/dev/null)
wait "$EXPIRING_BUSY_PID"
cat "$WORK_DIR/expiring-busy.err"
# The token refresh is the first retry, so the first 503 is the second one
grep -F "Retry attempt #2 in 40ms" "$WORK_DIR/expiring-busy.err" >/dev/null

# Then, try it as Varlink service
mkdir -p /run/systemd/system/systemd-imdsd@.service.d/
cat >/run/systemd/system/systemd-imdsd@.service.d/50-env.conf <<EOF
[Service]
Environment=SYSTEMD_IMDS_VENDOR=test2
Environment=SYSTEMD_IMDS_DATA_URL=http://192.168.47.1:8088
Environment=SYSTEMD_IMDS_KEY_USERDATA=/userdata
Environment=SYSTEMD_IMDS_KEY_HOSTNAME=/hostname
Environment=SYSTEMD_IMDS_KEY_IPV6_PUBLIC=/ipv6
Environment=SYSTEMD_IMDS_KEY_SSH_KEY=/sshkey
EOF
systemctl daemon-reload
systemctl start systemd-imdsd.socket

assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=hostname)" "piff"
assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=userdata)" "$USERDATA"
assert_eq "$(/usr/lib/systemd/systemd-imds -u)" "$USERDATA"

# Configured well-known keys which IMDS does not have, like ssh-key on EC2 instances without a key pair.
# Twice, to also cover the negative cache.
for _ in 1 2; do
    for key in ssh_key ipv6_public; do
        # any other error fails the call
        out="$(varlinkctl call --graceful=io.systemd.InstanceMetadata.KeyNotFound /run/systemd/io.systemd.InstanceMetadata io.systemd.InstanceMetadata.Get "{\"wellKnown\":\"$key\"}")"
        # KeyNotFound has no parameters, a successful reply would have "data"
        assert_eq "$out" "{}"
    done
done
(! /usr/lib/systemd/systemd-imds --well-known=ssh-key 2>"$WORK_DIR/imds.err")
cat "$WORK_DIR/imds.err"
grep -F "Key not available." "$WORK_DIR/imds.err" >/dev/null

# A request waiting for a retry finds a negative cache entry, which another request wrote in the meantime.
# fake-imds answers /flaky with 503, so the first request keeps retrying. The second request runs like
# another instance of the service (same user, capabilities, and cache directory), but with a header which
# makes fake-imds answer 404, so it writes the negative cache entry. The first request never gets 404 from
# the network, so KeyNotFound can only come from the cache.
varlinkctl call --graceful=io.systemd.InstanceMetadata.KeyNotFound /run/systemd/io.systemd.InstanceMetadata io.systemd.InstanceMetadata.Get '{"key":"/flaky"}' >"$WORK_DIR/flaky.out" &
FLAKY_PID=$!
timeout 10 bash -c 'until test -e /run/fake-imds-flaky; do sleep 0.1; done'
(! systemd-run --wait --pipe --quiet --collect \
               -p User=systemd-imds \
               -p AmbientCapabilities="CAP_NET_ADMIN CAP_NET_BIND_SERVICE" \
               -E RUNTIME_DIRECTORY=/run/systemd/imds \
               "${IMDSD[@]}" --interface=veth-imds --extra-header="X-Fake-IMDS-Not-Found: 1" /flaky)
wait "$FLAKY_PID"
assert_eq "$(cat "$WORK_DIR/flaky.out")" "{}"

/usr/lib/systemd/systemd-imds
/usr/lib/systemd/systemd-imds --import 2>&1 | tee "$WORK_DIR/import.log"
# Expect no generic error messages.
(! grep -F "io.systemd.System" "$WORK_DIR/import.log" >/dev/null)

assert_eq "$(cat /run/credstore/firstboot.hostname)" "piff"
assert_eq "$(cat /run/credstore/acredtest)" "avalue"
test ! -e /run/credstore/ssh.authorized_keys.root

# A failed public address lookup fails the import, like any other well-known key lookup. Use a key with a
# value which is not an IP address.
echo "Environment=SYSTEMD_IMDS_KEY_IPV4_PUBLIC=/hostname" >>/run/systemd/system/systemd-imdsd@.service.d/50-env.conf
systemctl daemon-reload
(! /usr/lib/systemd/systemd-imds --import 2>"$WORK_DIR/import.err")
cat "$WORK_DIR/import.err"
grep -F "Failed to parse IP address 'piff'" "$WORK_DIR/import.err" >/dev/null

# Lock down IMDS access to imdsd (systemd.imds.network=locked), with the networking which
# "systemd-imdsd --setup-network" generates and networkd applies. This needs IMDS at its usual link-local
# address, as the prohibit route covers only that.
ip -n imds addr add 169.254.169.254/32 dev veth-imds-peer
IMDSD_LOCKED=("${IMDSD[@]}" --data-url=http://169.254.169.254:8088 --address-ipv4=169.254.169.254)

# Unlocked mode has no prohibit route, and keeps reverse path filtering
SYSTEMD_PROC_CMDLINE=systemd.imds.network=unlocked "${IMDSD[@]}" --address-ipv4=169.254.169.254 --setup-network 2>&1 | tee "$WORK_DIR/setup-network-unlocked.log"
cat /run/systemd/network/85-imds-early.network
(! grep -F -e "Type=prohibit" -e "IPv4ReversePathFilter=" /run/systemd/network/85-imds-early.network >/dev/null)
(! grep -F "net.ipv4.conf.all.rp_filter" "$WORK_DIR/setup-network-unlocked.log" >/dev/null)

SYSTEMD_PROC_CMDLINE=systemd.imds.network=locked "${IMDSD_LOCKED[@]}" --setup-network 2>&1 | tee "$WORK_DIR/setup-network.log"
cat /run/systemd/network/85-imds-early.network
grep -Fx "Type=prohibit" /run/systemd/network/85-imds-early.network >/dev/null
grep -Fx "IPv4ReversePathFilter=no" /run/systemd/network/85-imds-early.network >/dev/null

# The generated .network matches physical Ethernet links only, and asks for DHCP. Apply it to the veth
# instead, with its static address.
mkdir -p /run/systemd/network/85-imds-early.network.d
cat >/run/systemd/network/85-imds-early.network.d/50-test.conf <<EOF
[Match]
Kind=
Name=veth-imds

[Network]
DHCP=no
Address=192.168.47.11/24
EOF

systemctl start systemd-networkd
networkctl reload
/usr/lib/systemd/systemd-networkd-wait-online --interface=veth-imds --timeout=30
networkctl status veth-imds
ip route show table all
ip rule show
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.veth-imds.rp_filter
assert_eq "$(sysctl -n net.ipv4.conf.veth-imds.rp_filter)" 0

# imdsd marks its sockets, which routes them around the prohibit route. IMDS's replies carry no mark, so
# this also needs reverse path filtering off, which the generated .network does on the link. But the kernel
# applies the maximum of that and net.ipv4.conf.all.rp_filter, which some distributions turn on (e.g.
# Ubuntu). Then the reverse path filter still drops the replies.
if [[ "$(sysctl -n net.ipv4.conf.all.rp_filter)" == 0 ]]; then
    (! grep -F "net.ipv4.conf.all.rp_filter" "$WORK_DIR/setup-network.log" >/dev/null)
    assert_eq "$("${IMDSD_LOCKED[@]}" --interface=veth-imds /hostname)" "piff"
else
    grep -F "net.ipv4.conf.all.rp_filter=" "$WORK_DIR/setup-network.log" >/dev/null
    # Do not wait for imdsd's overall 40s timeout (too annoying); instead, check that reverse path
    # filtering drops the replies
    rp_filter_drops() { nstat -asz TcpExtIPReversePathFilter | awk '/IPReversePathFilter/ { print $2 }'; }
    DROPS="$(rp_filter_drops)"
    assert_rc 124 timeout 5 "${IMDSD_LOCKED[@]}" --interface=veth-imds /hostname
    (( "$(rp_filter_drops)" > DROPS ))

    # The documented workaround. Only apply this file: all sysctl.d files would also reset the link's
    # setting, which networkd configures after them during boot.
    RP_FILTER_ALL="$(sysctl -n net.ipv4.conf.all.rp_filter)"
    mkdir -p /run/sysctl.d
    echo "net.ipv4.conf.all.rp_filter = 0" >/run/sysctl.d/90-imds.conf
    /usr/lib/systemd/systemd-sysctl /run/sysctl.d/90-imds.conf
    sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.veth-imds.rp_filter
    assert_eq "$("${IMDSD_LOCKED[@]}" --interface=veth-imds /hostname)" "piff"
fi

# Everybody else gets blocked
(! bash -c 'echo >/dev/tcp/169.254.169.254/8088' 2>"$WORK_DIR/connect.err")
cat "$WORK_DIR/connect.err"
grep -F "Permission denied" "$WORK_DIR/connect.err" >/dev/null
