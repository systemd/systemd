#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v ssh >/dev/null || ! command -v sshd >/dev/null ; then
    echo "ssh/sshd not found, skipping test." >&2
    exit 77
fi

systemctl -q is-active sshd-unix-local.socket

if test -e /dev/vsock ; then
    systemctl -q is-active sshd-vsock.socket
fi

if test -d /run/host/unix-export ; then
    systemctl -q is-active sshd-unix-export.socket
fi

# FIXME: sshd seems to crash inside asan currently, skip the actual ssh test hence
if [[ -v ASAN_OPTIONS ]] ; then
    exit 0
fi

ROOTID=$(mktemp -u)

removesshid() {
    rm -f "$ROOTID" "$ROOTID".pub
}

ssh-keygen -N '' -C '' -t rsa -f "$ROOTID"

# shellcheck disable=SC2174
mkdir -p -m 0700 /root/.ssh
# Add a newline in case authorized_keys wasn't terminated correctly.
echo >>/root/.ssh/authorized_keys
cat "$ROOTID".pub >>/root/.ssh/authorized_keys

# set root pw to "foo", just to set it to something valid
# shellcheck disable=SC2016
usermod -p '$5$AAy6BYJ6rzz.QELv$6LpVEU3/RQmVz.svHu/33qoJWWWzZuJ3DM2fo9JgcUD' root
usermod -U root

mkdir -p /etc/ssh
test -f /etc/ssh/ssh_host_rsa_key || ssh-keygen -t rsa -C '' -N '' -f /etc/ssh/ssh_host_rsa_key

SSHD_CONF_P="/etc/ssh/sshd_config.d/test.conf"
mkdir -p "$(basename ${SSHD_CONF_P})"
{
    echo "PermitRootLogin yes"
    echo "LogLevel DEBUG3"
} >"${SSHD_CONF_P}"
rm_sshd_conf() {
    rm -f "${SSHD_CONF_P}"
}
trap rm_sshd_conf EXIT

test -f /etc/ssh/ssh_config || {
    echo 'Include /etc/ssh/ssh_config.d/*.conf'
    echo 'Include /usr/etc/ssh/ssh_config.d/*.conf'
} >/etc/ssh/ssh_config

# ssh wants this dir around, but distros cannot agree on a common name for it, let's just create all that are aware of distros use
mkdir -p /usr/share/empty.sshd /var/empty /var/empty/sshd /run/sshd

ssh -o StrictHostKeyChecking=no -v -i "$ROOTID" .host cat /etc/machine-id | cmp - /etc/machine-id
ssh -o StrictHostKeyChecking=no -v -i "$ROOTID" unix/run/ssh-unix-local/socket cat /etc/machine-id | cmp - /etc/machine-id
ssh -o StrictHostKeyChecking=no -v -i "$ROOTID" machine/.host cat /etc/machine-id | cmp - /etc/machine-id

modprobe vsock_loopback || :
if test -e /dev/vsock -a -d /sys/module/vsock_loopback ; then
    ssh -o StrictHostKeyChecking=no -v -i "$ROOTID" vsock/1 cat /etc/machine-id | cmp - /etc/machine-id

    if ! command -v scp >/dev/null ; then
        echo "scp not found, skipping subtest" >&2
    else
        OUT_FILE=$(mktemp -u)
        scp -o StrictHostKeyChecking=no -v -i "$ROOTID" vsock%1:/etc/machine-id "$OUT_FILE"
        cmp "$OUT_FILE" /etc/machine-id
        rm -f "$OUT_FILE"
    fi
fi

# Test mptcp/ via a loopback sshd socket. If MPTCP is not available in the kernel, listen via plain TCP
# instead, which also covers systemd-ssh-proxy's fallback to TCP.
SOCKET_PROTOCOL=
if [[ "$(cat /proc/sys/net/mptcp/enabled 2>/dev/null)" == 1 ]]; then
    SOCKET_PROTOCOL="SocketProtocol=mptcp"
fi

# "localhost" might resolve to 127.0.0.1 or ::1 (or both), hence listen on both, if IPv6 is available
LISTEN_IPV6=
if [[ -e /proc/net/if_inet6 ]]; then
    LISTEN_IPV6="ListenStream=[::1]:2222"
fi

cat >/run/systemd/system/sshd-mptcp-test.socket <<EOF
[Socket]
ListenStream=127.0.0.1:2222
$LISTEN_IPV6
$SOCKET_PROTOCOL
FreeBind=yes
Accept=yes
EOF

cat >/run/systemd/system/sshd-mptcp-test@.service <<EOF
[Service]
ExecStart=-$(command -v sshd) -i
StandardInput=socket
EOF

rm_mptcp_units() {
    systemctl stop sshd-mptcp-test.socket
    rm -f /run/systemd/system/sshd-mptcp-test.socket /run/systemd/system/sshd-mptcp-test@.service
    systemctl daemon-reload
    rm_sshd_conf
}
trap rm_mptcp_units EXIT

systemctl daemon-reload
systemctl start sshd-mptcp-test.socket

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$ROOTID" -p 2222)

ssh "${SSH_OPTS[@]}" -v mptcp/127.0.0.1 cat /etc/machine-id | cmp - /etc/machine-id
# "localhost" goes through getaddrinfo()
ssh "${SSH_OPTS[@]}" -v mptcp/localhost cat /etc/machine-id | cmp - /etc/machine-id

# Interface suffixes are only valid for IPv6 link-local addresses, and required for them. Check for the
# specific error messages, since the commands would fail anyway, as nothing listens there.
(! /usr/lib/systemd/systemd-ssh-proxy mptcp/127.0.0.1%lo 2222 2>&1 >/dev/null </dev/null) | grep "Interface suffix is only supported for IPv6 link-local addresses" >/dev/null
(! /usr/lib/systemd/systemd-ssh-proxy mptcp/::1%lo 2222 2>&1 >/dev/null </dev/null) | grep "Interface suffix is only supported for IPv6 link-local addresses" >/dev/null
(! /usr/lib/systemd/systemd-ssh-proxy mptcp/fe80::1 2222 2>&1 >/dev/null </dev/null) | grep "IPv6 link-local addresses require an interface suffix" >/dev/null
(! /usr/lib/systemd/systemd-ssh-proxy mptcp/fe80::1%nosuchif0 2222 2>&1 >/dev/null </dev/null) | grep "Network interface of 'fe80::1%nosuchif0' does not exist" >/dev/null

if ! command -v scp >/dev/null ; then
    echo "scp not found, skipping subtest" >&2
else
    OUT_FILE=$(mktemp -u)
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$ROOTID" -P 2222 -v mptcp%127.0.0.1:/etc/machine-id "$OUT_FILE"
    cmp "$OUT_FILE" /etc/machine-id
    rm -f "$OUT_FILE"
fi
