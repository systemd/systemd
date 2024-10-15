#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# TODO/FIXME:
#   - we should probably have something like "udevadm verify" but for .network files
#     (networkctl verify?) so we can check that all directives are in correct sections
#   - according to dracut.cmdline(7) <peer> address can also be followed by /CIDR,
#     but this doesn't seem to work with sd-network-generator

if [[ -n "${1:-}" ]]; then
    GENERATOR_BIN=$1
elif [[ -x /usr/lib/systemd/systemd-network-generator ]]; then
    GENERATOR_BIN=/usr/lib/systemd/systemd-network-generator
elif [[ -x /lib/systemd/systemd-network-generator ]]; then
    GENERATOR_BIN=/lib/systemd/systemd-network-generator
else
    exit 1
fi

# See: https://github.com/systemd/systemd/pull/29888#issuecomment-1796187440
unset NOTIFY_SOCKET

WORK_DIR="$(mktemp --directory --tmpdir "test-network-generator-conversion.XXXXXX")"
# shellcheck disable=SC2064
trap "rm -rf '$WORK_DIR'" EXIT

# Convert octal netmask to CIDR notation (e.g. 255.255.255.0 => 24)
netmask_to_cidr() (
    set +x

    local netmask="${1:?}"
    local x bits=0

    # shellcheck disable=SC2086
    x="0$(printf "%o" ${netmask//./ })"
    while [[ "$x" -gt 0 ]]; do
        ((bits += x % 2))
        ((x >>= 1))
    done

    echo "$bits"
)

run_network_generator() {
    local stderr

    rm -rf "${WORK_DIR:?}"/*
    stderr="$WORK_DIR/stderr"
    if ! SYSTEMD_LOG_LEVEL="info" "$GENERATOR_BIN" --root "$WORK_DIR" 2>"$stderr"; then
        echo >&2 "Generator failed when parsing $SYSTEMD_PROC_CMDLINE"
        cat >&2 "$stderr"
        return 1
    fi

    if [[ -s "$stderr" ]]; then
        echo >&2 "Generator generated unexpected messages on stderr"
        cat >&2 "$stderr"
        return 1
    fi

    ls -l "$WORK_DIR/run/systemd/network/"

    rm -f "$stderr"
    return 0
}

check_dhcp() {
    local dhcp="${1:?}"
    local network_file="${2:?}"

    case "$dhcp" in
        dhcp)
            grep -q "^DHCP=ipv4$" "$network_file"
            ;;
        dhcp6)
            grep -q "^DHCP=ipv6$" "$network_file"
            ;;
        on|any)
            grep -q "^DHCP=yes$" "$network_file"
            ;;
        none|off)
            grep -q "^DHCP=no$" "$network_file"
            grep -q "^LinkLocalAddressing=no$" "$network_file"
            grep -q "^IPv6AcceptRA=no$" "$network_file"
            ;;
        auto6|ibft)
            grep -q "^DHCP=no$" "$network_file"
            ;;
        either6)
            grep -q "^DHCP=ipv6$" "$network_file"
            ;;
        link6)
            grep -q "^DHCP=no$" "$network_file"
            grep -q "^LinkLocalAddressing=ipv6$" "$network_file"
            grep -q "^IPv6AcceptRA=no$" "$network_file"
            ;;
        link-local)
            grep -q "^DHCP=no$" "$network_file"
            grep -q "^LinkLocalAddressing=yes$" "$network_file"
            grep -q "^IPv6AcceptRA=no$" "$network_file"
            ;;
        *)
            echo >&2 "Invalid assignment $cmdline"
            return 1
    esac

    return 0
}

# Check the shortest ip= variant, i.e.:
#   ip={dhcp|on|any|dhcp6|auto6|either6|link6|link-local}
#
# Note:
#   - dracut also supports single-dhcp
#   - link-local is supported only by systemd-network-generator
check_one_dhcp() {
    local cmdline="${1:?}"
    local dhcp="${cmdline#ip=}"
    local network_file

    SYSTEMD_LOG_LEVEL=debug SYSTEMD_PROC_CMDLINE="$cmdline" run_network_generator
    network_file="${WORK_DIR:?}/run/systemd/network/71-default.network"
    cat "$network_file"

    check_dhcp "$dhcp" "$network_file"

    return 0
}

# Similar to the previous one, but with slightly more fields:
#   ip=<interface>:{dhcp|on|any|dhcp6|auto6|link6|link-local}[:[<mtu>][:<macaddr>]]
#
# Same notes apply as well.
check_one_interface_dhcp() {
    local cmdline="${1:?}"
    local ifname dhcp mtu mac network_file

    IFS=":" read -r ifname dhcp mtu mac <<< "${cmdline#ip=}"

    SYSTEMD_LOG_LEVEL=debug SYSTEMD_PROC_CMDLINE="$cmdline" run_network_generator
    network_file="${WORK_DIR:?}/run/systemd/network/70-$ifname.network"
    cat "$network_file"

    grep -q "^Name=$ifname$" "$network_file"
    check_dhcp "$dhcp" "$network_file"
    [[ -n "$mtu" ]] && grep -q "^MTUBytes=$mtu$" "$network_file"
    [[ -n "$mac" ]] && grep -q "^MACAddress=$mac$" "$network_file"

    return 0
}

# Check the "long" ip= formats, i.e:
#   ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<mtu>][:<macaddr>]
#   ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<dns1>][:<dns2>]]
check_one_long() {
    local cmdline="${1:?}"
    local ip peer gateway netmask hostname ifname dhcp arg1 arg2 network_file cidr stderr tmp

    # To make parsing a bit easier when IPv6 is involved, replace all colons between [] with #, ...
    tmp="$(echo "${cmdline#ip=}" | sed -re ':l; s/(\[[^]:]*):/\1#/; tl')"
    # ... drop the now unnecessary [] and split the string into colon separated fields as usual, ...
    IFS=":" read -r ip peer gateway netmask hostname ifname dhcp arg1 arg2 <<<"${tmp//[\[\]]}"
    # ... and then replace # back to colons for fields that might contain an IPv6 address.
    ip="${ip//#/:}"
    peer="${peer//#/:}"
    gateway="${gateway//#/:}"
    arg1="${arg1//#/:}"
    arg2="${arg2//#/:}"

    SYSTEMD_LOG_LEVEL=debug SYSTEMD_PROC_CMDLINE="$cmdline" run_network_generator

    if [[ -n "$ifname" ]]; then
        network_file="${WORK_DIR:?}/run/systemd/network/70-$ifname.network"
        grep -q "^Name=$ifname$" "$network_file"
    else
        network_file="${WORK_DIR:?}/run/systemd/network/71-default.network"
        grep -q "^Kind=!\*$" "$network_file"
    fi

    cat "$network_file"

    if [[ -n "$ip" && -n "$netmask" ]]; then
        # The "ip" and "netmask" fields are merged together into an IP/CIDR value
        if [[ "$netmask" =~ ^[0-9]+$ ]]; then
            cidr="$netmask"
        else
            cidr="$(netmask_to_cidr "$netmask")"
        fi

        grep -q "^Address=$ip/$cidr$" "$network_file"
    else
        (! grep -q "^Address=" "$network_file")
    fi
    # If the "dhcp" field is empty, it defaults to "off"
    [[ -z "$dhcp" ]] && dhcp="off"
    [[ -n "$peer" ]] && grep -q "^Peer=$peer$" "$network_file"
    [[ -n "$gateway" ]] && grep -q "^Gateway=$gateway$" "$network_file"
    [[ -n "$hostname" ]] && grep -q "^Hostname=$hostname$" "$network_file"
    check_dhcp "$dhcp" "$network_file"

    # If the first optional argument is empty, assume the first variant
    # See: https://github.com/dracutdevs/dracut/blob/4d594210d6ef4f04a9dbadacea73e9461ded352d/modules.d/40network/net-lib.sh#L533
    if [[ -z "$arg1" || "$arg1" =~ ^[0-9]+$ ]]; then
        # => [:[<mtu>][:<macaddr>]
        [[ -n "$arg1" ]] && grep -q "^MTUBytes=$arg1$" "$network_file"
        [[ -n "$arg2" ]] && grep -q "^MACAddress=$arg2$" "$network_file"
    else
        # => [:[<dns1>][:<dns2>]]
        grep -q "^DNS=$arg1$" "$network_file"
        [[ -n "$arg2" ]] && grep -q "^DNS=$arg2$" "$network_file"
    fi

    return 0
}

# Check if the generated .network files match the expected stored ones
TEST_DATA="$(dirname "$0")/testdata/test-network-generator-conversion"
for f in "$TEST_DATA"/test-*.input; do
    fname="${f##*/}"
    out="$(mktemp --directory "${WORK_DIR:?}/${fname%%.input}.XXX")"

    # shellcheck disable=SC2046
    "$GENERATOR_BIN" --root "$out" -- $(cat "$f")

    if ! diff -u "$out/run/systemd/network" "${f%.input}.expected"; then
        echo >&2 "**** Unexpected output for $f"
        exit 1
    fi

    rm -rf "${out:?}"
done

# Now generate bunch of .network units on the fly and check if they contain expected
# directives & values

# ip={dhcp|on|any|dhcp6|auto6|either6|link6|link-local}
for dhcp in dhcp on any dhcp6 auto6 either6 link6 link-local off none ibft; do
    check_one_dhcp "ip=$dhcp"
done

# ip=<interface>:{dhcp|on|any|dhcp6|auto6|link6|link-local}[:[<mtu>][:<macaddr>]]
COMMAND_LINES=(
    "ip=foo:dhcp"
    "ip=bar:dhcp6"
    "ip=linklocal99:link-local"
    "ip=baz1:any:666"
    "ip=baz1:any:128:52:54:00:a7:8f:ac"
)
for cmdline in "${COMMAND_LINES[@]}"; do
    check_one_interface_dhcp "$cmdline"
done

# ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<mtu>][:<macaddr>]
# ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<dns1>][:<dns2>]]
COMMAND_LINES=(
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:255.255.255.0:hello-world.local:dummy99:off"
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:24:hello-world.local:dummy99:off"
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:255.255.255.0:hello-world.local:dummy99:off:123"
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:255.255.255.0:hello-world.local:dummy99:off:123:52:54:00:a7:8f:ac"
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:255.255.255.0:hello-world.local:dummy99:off::52:54:00:a7:8f:ac"
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:255.255.255.0:hello-world.local:dummy99:off:1.2.3.2"
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:255.255.255.0:hello-world.local:dummy99:off:1.2.3.2:1.2.3.3"
    "ip=192.168.0.2::192.168.0.1:255.255.128.0::foo1:off"
    "ip=192.168.0.2::192.168.0.1:17::foo1:off"
    "ip=10.0.0.1:::255.255.255.0::foo99:off"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off"
    "ip=[fdef:c400:bd01:1096::2]:[fdef:c400:bd01:1096::99]::64::ipv6:off"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off:666"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off:666:52:54:00:a7:8f:ac"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off::52:54:00:a7:8f:ac"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off:[fdef:c400:bd01:1096::aaaa]"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off:[fdef:c400:bd01:1096::aaaa]:[fdef:c400:bd01:1096::bbbb]"
    "ip=:::::dhcp99:any"
    "ip=:::::dhcp99:dhcp6:666"
    "ip=:::::dhcp99:dhcp6:666:52:54:00:a7:8f:ac"
    "ip=:::::dhcp99:dhcp6:10.0.0.128"
    "ip=:::::dhcp99:dhcp6:10.0.0.128:10.0.0.129"
    "ip=:::::dhcp99:dhcp6:10.0.0.128:[fdef:c400:bd01:1096::bbbb]"
    "ip=::::::any"
    "ip=::::::ibft"
)
for cmdline in "${COMMAND_LINES[@]}"; do
    check_one_long "$cmdline"
done

INVALID_COMMAND_LINES=(
    "ip=foo"
    "ip=:::::::"
    "ip=:::::::foo"
    "ip=10.0.0:::255.255.255.0::foo99:off"
    "ip=10.0.0.1:::255.255.255::foo99:off"
    "ip=10.0.0.1:::255.255.255.0:invalid_hostname:foo99:off"
    "ip=10.0.0.1:::255.255.255.0::verylonginterfacename:off"
    "ip=:::::dhcp99:dhcp6:4294967296"
    "ip=:::::dhcp99:dhcp6:-1"
    "ip=:::::dhcp99:dhcp6:666:52:54:00"
    "ip=1.2.3.4:2.3.4.5:1.2.3.1:255.255.255.0:hello-world.local:dummy99:off::"
    "ip=fdef:c400:bd01:1096::2::[fdef:c400:bd01:1096::1]:64::ipv6:off:[fdef:c400:bd01:1096::aaaa]"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off::"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off:foo"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off:[fdef:c400:bd01:1096::aaaa]:foo"
    "ip=[fdef:c400:bd01:1096::2]::[fdef:c400:bd01:1096::1]:64::ipv6:off:[fdef:c400:bd01:1096::aaaa]:[fdef:c400:bd01:1096::bbbb]:"
    "ip=:::::dhcp99:dhcp6:10.0.0.128:10.0.0.129:"
    "ip=:::::dhcp99:dhcp6:10.0.0.128:[fdef:c400:bd01:1096::bbbb]:"
)
for cmdline in "${INVALID_COMMAND_LINES[@]}"; do
    (! SYSTEMD_LOG_LEVEL=debug SYSTEMD_PROC_CMDLINE="$cmdline" "$GENERATOR_BIN" --root "$WORK_DIR")
done
