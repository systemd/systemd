#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: ts=4 sw=4 tw=0 et:

set -eux
set -o pipefail

: >/failed

RUN_OUT="$(mktemp)"

run() {
    : >"$RUN_OUT"
    "$@" |& tee "$RUN_OUT"
}

### SETUP ###
# Configure network
hostnamectl hostname primary.dns.systemd
echo "1.2.3.1 primary.dns.systemd" >>/etc/hosts

mkdir -p /etc/systemd/network
cat >/etc/systemd/network/dns0.netdev <<EOF
[NetDev]
Name=dns0
Kind=dummy
EOF
cat >/etc/systemd/network/dns0.network <<EOF
[Match]
Name=dns0

[Network]
Address=1.2.3.1/24
DNSSEC=allow-downgrade
DNS=1.2.3.1
EOF

echo "FallbackDNS=" >>/etc/systemd/resolved.conf
ln -svf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# Sign the root zone
keymgr . generate algorithm=ECDSAP256SHA256 ksk=yes zsk=yes
# Create a trust anchor for resolved with our root zone
mkdir -p "/etc/dnssec-trust-anchors.d/"
keymgr . dnskey | sed 's/ DNSKEY/ IN DNSKEY/g' >/etc/dnssec-trust-anchors.d/root.positive
# Create a bind-compatible trust anchor (for delv)
echo 'trust-anchors {' >/etc/bind.keys
keymgr . dnskey | sed -r 's/^\. DNSKEY ([0-9]+ [0-9]+ [0-9]+) (.+)$/. static-key \1 "\2";/g' >>/etc/bind.keys
echo '};' >>/etc/bind.keys

# Start the services
systemctl unmask systemd-networkd systemd-resolved
systemctl start systemd-networkd systemd-resolved
systemctl start knot
# Wait a bit for the keys to propagate
sleep 4

networkctl status
resolvectl status
resolvectl log-level debug

### SETUP END ###

: "--- Basic resolved tests ---"
# Issue: https://github.com/systemd/systemd/issues/22229
# PR: https://github.com/systemd/systemd/pull/22231
FILTERED_NAMES=(
    "0.in-addr.arpa"
    "255.255.255.255.in-addr.arpa"
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
    "hello.invalid"
)

for name in "${FILTERED_NAMES[@]}"; do
    run host "$name" && { echo >&2 "unexpected success"; exit 1; }
    grep -F "NXDOMAIN" "$RUN_OUT"
done

# Follow-up
# Issue: https://github.com/systemd/systemd/issues/22401
# PR: https://github.com/systemd/systemd/pull/22414
run dig +noall +authority +comments SRV .
grep -F "status: NOERROR" "$RUN_OUT"
grep -E "IN\s+SOA\s+primary\.dns\.systemd\." "$RUN_OUT"

: "--- ZONE: unsigned.systemd ---"
run dig @1.2.3.1 +short unsigned.systemd
grep -F "1.2.3.101" "$RUN_OUT"
run resolvectl query unsigned.systemd
grep -F "unsigned.systemd: 1.2.3.10" "$RUN_OUT"
grep -F "authenticated: no" "$RUN_OUT"
run dig @1.2.3.1 +short MX unsigned.systemd
grep -F "15 mail.unsigned.systemd." "$RUN_OUT"
run resolvectl query --legend=no -t MX unsigned.systemd
grep -F "unsigned.systemd IN MX 15 mail.unsigned.systemd" "$RUN_OUT"

: "--- ZONE: dns.systemd ---"
# Check the trust chain (with and without systemd-resolved in between
# Issue: https://github.com/systemd/systemd/issues/22002
run delv @1.2.3.1 dns.systemd
grep -F "; fully validated" "$RUN_OUT"
run delv dns.systemd
grep -F "; fully validated" "$RUN_OUT"

run dig +short dns.systemd
grep -F "1.2.3.10" "$RUN_OUT"
run resolvectl query dns.systemd
grep -F "dns.systemd: 1.2.3.10" "$RUN_OUT"
grep -F "authenticated: yes" "$RUN_OUT"
run dig @1.2.3.1 +short MX dns.systemd
grep -F "10 mail.dns.systemd." "$RUN_OUT"
run resolvectl query --legend=no -t MX dns.systemd
grep -F "dns.systemd IN MX 10 mail.dns.systemd" "$RUN_OUT"


touch /testok
rm /failed
