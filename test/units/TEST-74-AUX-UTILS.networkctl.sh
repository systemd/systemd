#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    systemctl stop systemd-networkd

    if [[ -v NETWORK_NAME && -v NETDEV_NAME && -v LINK_NAME ]]; then
        rm -fvr {/usr/lib,/etc,/run}/systemd/network/"$NETWORK_NAME" "/run/lib/systemd/network/$NETDEV_NAME" \
            {/usr/lib,/etc}/systemd/network/"$LINK_NAME" "/etc/systemd/network/${NETWORK_NAME}.d" \
            "new" "+4"
    fi

    rm -f /run/systemd/networkd.conf.d/10-hoge.conf
    if [[ -v VERIFY_DIR ]]; then
        rm -rf "$VERIFY_DIR"
    fi
}

trap at_exit EXIT

systemctl unmask systemd-networkd.service
systemctl start systemd-networkd.service

export NETWORK_NAME="10-networkctl-test-$RANDOM.network"
export NETDEV_NAME="10-networkctl-test-$RANDOM.netdev"
export LINK_NAME="10-networkctl-test-$RANDOM.link"
cat >"/usr/lib/systemd/network/$NETWORK_NAME" <<EOF
[Match]
Name=test
EOF

# Test files

networkctl mask --runtime "donotexist.network"
assert_eq "$(readlink /run/systemd/network/donotexist.network)" "/dev/null"
networkctl unmask "donotexist.network" # unmask should work even without --runtime
[[ ! -e /run/systemd/network/donotexist.network ]]

touch /usr/lib/systemd/network/donotexist.network
(! networkctl unmask "donotexist.network")
rm /usr/lib/systemd/network/donotexist.network

(! networkctl cat "/usr/lib/systemd/network/$NETWORK_NAME")
networkctl cat "$NETWORK_NAME" | tail -n +2 | cmp - "/usr/lib/systemd/network/$NETWORK_NAME"

cat >new <<EOF
[Match]
Name=test2
EOF

(! networkctl edit "/usr/lib/systemd/network/$NETWORK_NAME")
EDITOR='mv new' script -ec 'networkctl edit --runtime "$NETWORK_NAME"' /dev/null
(! networkctl mask --runtime "$NETWORK_NAME")
printf '%s\n' '[Match]' 'Name=test2' | cmp - "/run/systemd/network/$NETWORK_NAME"

networkctl mask "$NETWORK_NAME"
assert_eq "$(readlink "/etc/systemd/network/$NETWORK_NAME")" "/dev/null"
(! networkctl edit "$NETWORK_NAME")
(! networkctl edit --runtime "$NETWORK_NAME")
(! networkctl cat "$NETWORK_NAME")
networkctl unmask "$NETWORK_NAME"

EDITOR='true' script -ec 'networkctl edit "$NETWORK_NAME"' /dev/null
printf '%s\n' '[Match]' 'Name=test2' | cmp - "/etc/systemd/network/$NETWORK_NAME"

(! networkctl mask "$NETWORK_NAME")
(! EDITOR='true' script -ec 'networkctl edit --runtime "$NETWORK_NAME"' /dev/null)

cat >"+4" <<EOF
[Network]
IPv6AcceptRA=no
EOF

EDITOR='cp' script -ec 'networkctl edit "$NETWORK_NAME" --drop-in test' /dev/null
cmp "+4" "/etc/systemd/network/${NETWORK_NAME}.d/test.conf"

networkctl cat "$NETWORK_NAME" | grep '^# ' |
    cmp - <(printf '%s\n' "# /etc/systemd/network/$NETWORK_NAME" "# /etc/systemd/network/${NETWORK_NAME}.d/test.conf")

cat >"/usr/lib/systemd/network/$LINK_NAME" <<EOF
[Match]
OriginalName=test2

[Link]
Alias=test_alias
EOF

SYSTEMD_LOG_LEVEL=debug EDITOR='true' script -ec 'networkctl edit "$LINK_NAME"' /dev/null
cmp "/usr/lib/systemd/network/$LINK_NAME" "/etc/systemd/network/$LINK_NAME"

# The interface test2 does not exist, hence the below do not work.
(! networkctl cat @test2)
(! networkctl cat @test2:netdev)
(! networkctl cat @test2:link)
(! networkctl cat @test2:network)

# create .netdev file at last, otherwise, the .link file will not be applied to the interface.
networkctl edit --stdin --runtime "$NETDEV_NAME" <<EOF
[NetDev]
Name=test2
Kind=dummy
EOF

networkctl cat "$NETDEV_NAME" | grep -v '^# ' |
    cmp - <(printf '%s\n' "[NetDev]" "Name=test2" "Kind=dummy")

# wait for the interface being created and configured.
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-networkd-wait-online -i test2:carrier --timeout 20

networkctl cat @test2:network | cmp - <(networkctl cat "$NETWORK_NAME")
networkctl cat @test2:netdev | cmp - <(networkctl cat "$NETDEV_NAME")
for c in "$NETWORK_NAME" "$NETDEV_NAME"; do
    assert_in "$(networkctl cat "$c" | head -n1)" "$(networkctl cat @test2:all)"
done

(! networkctl edit @test2:all)

EDITOR='cp' script -ec 'networkctl edit @test2 --drop-in test2.conf' /dev/null
cmp "+4" "/etc/systemd/network/${NETWORK_NAME}.d/test2.conf"

SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-networkd-wait-online -i test2:carrier --timeout 20
(! EDITOR='true' script -ec 'networkctl edit @test2 --runtime --drop-in test2.conf' /dev/null)

ip_link="$(ip link show test2)"
if systemctl --quiet is-active systemd-udevd; then
    networkctl cat @test2:link | cmp - <(networkctl cat "$LINK_NAME")
    assert_in "$(networkctl cat "$LINK_NAME" | head -n1)" "$(networkctl cat @test2:all)"

    assert_in 'alias test_alias' "$ip_link"
fi

# Test verify

VERIFY_DIR="$(mktemp -d)"
mkdir "$VERIFY_DIR/other"
cat >"$VERIFY_DIR/10-good.network" <<EOF
[Match]
Name=test3

[Network]
DHCP=yes
EOF
cp "$VERIFY_DIR/10-good.network" "$VERIFY_DIR/other/10-good.network"
cat >"$VERIFY_DIR/10-unknown-key.network" <<EOF
[Match]
Name=test3

[Network]
DHCP=yes
Foo=bar
EOF
cat >"$VERIFY_DIR/10-no-match.network" <<EOF
[Network]
DHCP=yes
EOF
cat >"$VERIFY_DIR/10-condition.network" <<EOF
[Match]
Name=test3
Host=networkctl-test-no-such-host

[Network]
DHCP=yes
EOF
cat >"$VERIFY_DIR/10-condition-unknown-key.network" <<EOF
[Match]
Name=test3
Host=networkctl-test-no-such-host

[Network]
DHCP=yes
Foo=bar
EOF
cat >"$VERIFY_DIR/10-removed-key.network" <<EOF
[Match]
Name=test3

[Network]
L2TP=foo
EOF
cat >"$VERIFY_DIR/10-member.network" <<EOF
[Match]
Name=test3

[Network]
Bridge=test3-br
EOF
cat >"$VERIFY_DIR/10-mtu.network" <<EOF
[Match]
Name=test3

[Link]
MTUBytes=1400

[DHCP]
UseMTU=yes

[Network]
DHCP=yes
EOF
cat >"$VERIFY_DIR/10-good.netdev" <<EOF
[NetDev]
Name=test3
Kind=dummy
EOF
cat >"$VERIFY_DIR/10-unknown-key.netdev" <<EOF
[NetDev]
Name=test3
Kind=dummy
Foo=bar
EOF
cat >"$VERIFY_DIR/10-no-kind.netdev" <<EOF
[NetDev]
Name=test3
EOF
cat >"$VERIFY_DIR/10-bridge.netdev" <<EOF
[NetDev]
Name=test3-br
Kind=bridge
EOF
cat >"$VERIFY_DIR/10-wireguard.netdev" <<EOF
[NetDev]
Name=test3-wg
Kind=wireguard

[WireGuard]
PrivateKeyFile=$VERIFY_DIR/does-not-exist.key

[WireGuardPeer]
PublicKeyFile=$VERIFY_DIR/does-not-exist.key
AllowedIPs=10.0.0.0/24
EOF
cat >"$VERIFY_DIR/10-wireguard-no-key.netdev" <<EOF
[NetDev]
Name=test3-wg
Kind=wireguard

[WireGuardPeer]
AllowedIPs=10.0.0.0/24
EOF
cat >"$VERIFY_DIR/10-macsec.netdev" <<EOF
[NetDev]
Name=test3-macsec
Kind=macsec

[MACsecTransmitAssociation]
PacketNumber=1
KeyId=01
KeyFile=$VERIFY_DIR/does-not-exist.key
EOF
: >"$VERIFY_DIR/10-empty.network"
ln -s /dev/null "$VERIFY_DIR/10-masked.netdev"

VERIFY=(networkctl verify)

# Fails, and says why: $1 is the expected message, the rest are the files to verify.
assert_verify_fails() {
    local expected="$1" output
    shift

    if output="$("${VERIFY[@]}" "$@" 2>&1)"; then
        echo "FAIL: ${VERIFY[*]} $* unexpectedly succeeded" >&2
        return 1
    fi
    assert_in "$expected" "$output"
}

networkctl --help | grep '^  verify ' >/dev/null
(! "${VERIFY[@]}")

"${VERIFY[@]}" "$VERIFY_DIR/10-good.network" "$VERIFY_DIR/10-good.netdev"
# relative paths work too
(cd "$VERIFY_DIR" && "${VERIFY[@]}" 10-good.network)
# the same file name in two directories is two files, not a conflict, and the same file twice is one file
"${VERIFY[@]}" "$VERIFY_DIR/10-good.network" "$VERIFY_DIR/other/10-good.network"
"${VERIFY[@]}" "$VERIFY_DIR/10-good.netdev" "$VERIFY_DIR/10-good.netdev"
# a .network may refer to a .netdev given in the same invocation, in any order
output=$("${VERIFY[@]}" "$VERIFY_DIR/10-member.network" "$VERIFY_DIR/10-bridge.netdev" 2>&1)
assert_not_in "could not be found" "$output"
output=$("${VERIFY[@]}" "$VERIFY_DIR/10-bridge.netdev" "$VERIFY_DIR/10-member.network" 2>&1)
assert_not_in "could not be found" "$output"
# masked or empty files and files whose conditions do not match are skipped, as the daemon skips them
output=$("${VERIFY[@]}" "$VERIFY_DIR/10-empty.network" "$VERIFY_DIR/10-masked.netdev" 2>&1)
assert_in "Masked or empty, skipping" "$output"
output=$("${VERIFY[@]}" "$VERIFY_DIR/10-condition.network" 2>&1)
assert_in "Conditions do not match this host, skipping" "$output"
# key files are not read, so they need not exist, but they count as keys
"${VERIFY[@]}" "$VERIFY_DIR/10-wireguard.netdev"
output=$("${VERIFY[@]}" "$VERIFY_DIR/10-macsec.netdev" 2>&1)
assert_not_in "without key configured" "$output"
# a peer without a key is dropped with an error, as in the daemon, but the netdev itself still loads
output=$("${VERIFY[@]}" "$VERIFY_DIR/10-wireguard-no-key.netdev" 2>&1)
assert_in "without PublicKey= configured" "$output"

# a parser warning networkd would only log is an error here
assert_verify_fails "Unknown key 'Foo'" "$VERIFY_DIR/10-unknown-key.network"
assert_verify_fails "The configuration parser reported problems" "$VERIFY_DIR/10-unknown-key.network"
assert_verify_fails "The configuration parser reported problems" "$VERIFY_DIR/10-unknown-key.netdev"
# even in a file that is skipped otherwise, and even if the log level would hide the message
assert_verify_fails "Unknown key 'Foo'" "$VERIFY_DIR/10-condition-unknown-key.network"
SYSTEMD_LOG_LEVEL=err assert_verify_fails "Unknown key 'Foo'" "$VERIFY_DIR/10-unknown-key.network"
# a removed option is a warning like an unknown key
assert_verify_fails "Support for option L2TP= has been removed" "$VERIFY_DIR/10-removed-key.network"
assert_verify_fails "No valid settings found in the \[Match\] section" "$VERIFY_DIR/10-no-match.network"
# so are settings networkd would accept and then override or drop
assert_verify_fails "could not be found" "$VERIFY_DIR/10-member.network"
assert_verify_fails "Disabling UseMTU=" "$VERIFY_DIR/10-mtu.network"
assert_verify_fails "NetDev has no Kind= configured" "$VERIFY_DIR/10-no-kind.netdev"
# one bad file fails the whole invocation, wherever it is in the list
assert_verify_fails "NetDev has no Kind= configured" "$VERIFY_DIR/10-good.network" "$VERIFY_DIR/10-no-kind.netdev"
assert_verify_fails "NetDev has no Kind= configured" "$VERIFY_DIR/10-no-kind.netdev" "$VERIFY_DIR/10-good.network"
assert_verify_fails "Not a .network or .netdev file" "/usr/lib/systemd/network/$LINK_NAME"
assert_verify_fails "No such file or directory" "$VERIFY_DIR/does-not-exist.network"

mkdir -p /run/systemd/networkd.conf.d
cat >/run/systemd/networkd.conf.d/10-hoge.conf <<EOF
# TEST DROP-IN FILE
[Network]
SpeedMeter=yes
EOF

assert_in '# TEST DROP-IN FILE' "$(networkctl cat)"
