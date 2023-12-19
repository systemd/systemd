#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: ts=4 sw=4 tw=0 et:

# TODO:
#   - IPv6-only stack
#   - mDNS
#   - LLMNR
#   - DoT/DoH

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

RUN_OUT="$(mktemp)"

run() {
    "$@" |& tee "$RUN_OUT"
}

run_delv() {
    # Since [0] delv no longer loads /etc/(bind/)bind.keys by default, so we
    # have to do that explicitly for each invocation
    run delv -a /etc/bind.keys "$@"
}

disable_ipv6() {
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
}

enable_ipv6() {
    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    networkctl reconfigure dns0
    /usr/lib/systemd/systemd-networkd-wait-online --ipv4 --ipv6 --interface=dns0:routable --timeout=30
}

monitor_check_rr() (
    set +x
    set +o pipefail
    local since="${1:?}"
    local match="${2:?}"

    # Wait until the first mention of the specified log message is
    # displayed. We turn off pipefail for this, since we don't care about the
    # lhs of this pipe expression, we only care about the rhs' result to be
    # clean
    timeout -v 30s journalctl -u resolvectl-monitor.service --since "$since" -f --full | grep -m1 "$match"
)

restart_resolved() {
    systemctl stop systemd-resolved.service
    (! systemctl is-failed systemd-resolved.service)
    # Reset the restart counter since we call this method a bunch of times
    # and can occasionally hit the default rate limit
    systemctl reset-failed systemd-resolved.service
    systemctl start systemd-resolved.service
    systemctl service-log-level systemd-resolved.service debug
}

# Test for resolvectl, resolvconf
systemctl unmask systemd-resolved.service
systemctl enable --now systemd-resolved.service
systemctl service-log-level systemd-resolved.service debug
ip link add hoge type dummy
ip link add hoge.foo type dummy
resolvectl dns hoge 10.0.0.1 10.0.0.2
resolvectl dns hoge.foo 10.0.0.3 10.0.0.4
assert_in '10.0.0.1 10.0.0.2' "$(resolvectl dns hoge)"
assert_in '10.0.0.3 10.0.0.4' "$(resolvectl dns hoge.foo)"
resolvectl dns hoge 10.0.1.1 10.0.1.2
resolvectl dns hoge.foo 10.0.1.3 10.0.1.4
assert_in '10.0.1.1 10.0.1.2' "$(resolvectl dns hoge)"
assert_in '10.0.1.3 10.0.1.4' "$(resolvectl dns hoge.foo)"
if ! RESOLVCONF=$(command -v resolvconf 2>/dev/null); then
    TMPDIR=$(mktemp -d -p /tmp resolvconf-tests.XXXXXX)
    RESOLVCONF="$TMPDIR"/resolvconf
    ln -s "$(command -v resolvectl 2>/dev/null)" "$RESOLVCONF"
fi
echo nameserver 10.0.2.1 10.0.2.2 | "$RESOLVCONF" -a hoge
echo nameserver 10.0.2.3 10.0.2.4 | "$RESOLVCONF" -a hoge.foo
assert_in '10.0.2.1 10.0.2.2' "$(resolvectl dns hoge)"
assert_in '10.0.2.3 10.0.2.4' "$(resolvectl dns hoge.foo)"
echo nameserver 10.0.3.1 10.0.3.2 | "$RESOLVCONF" -a hoge.inet.ipsec.192.168.35
echo nameserver 10.0.3.3 10.0.3.4 | "$RESOLVCONF" -a hoge.foo.dhcp
assert_in '10.0.3.1 10.0.3.2' "$(resolvectl dns hoge)"
assert_in '10.0.3.3 10.0.3.4' "$(resolvectl dns hoge.foo)"

# Tests for _localdnsstub and _localdnsproxy
assert_in '127.0.0.53' "$(resolvectl query _localdnsstub)"
assert_in '_localdnsstub' "$(resolvectl query 127.0.0.53)"
assert_in '127.0.0.54' "$(resolvectl query _localdnsproxy)"
assert_in '_localdnsproxy' "$(resolvectl query 127.0.0.54)"

assert_in '127.0.0.53' "$(dig @127.0.0.53 _localdnsstub)"
assert_in '_localdnsstub' "$(dig @127.0.0.53 -x 127.0.0.53)"
assert_in '127.0.0.54' "$(dig @127.0.0.53 _localdnsproxy)"
assert_in '_localdnsproxy' "$(dig @127.0.0.53 -x 127.0.0.54)"

# Tests for mDNS and LLMNR settings
mkdir -p /run/systemd/resolved.conf.d
{
    echo "[Resolve]"
    echo "MulticastDNS=yes"
    echo "LLMNR=yes"
} >/run/systemd/resolved.conf.d/mdns-llmnr.conf
restart_resolved
# make sure networkd is not running.
systemctl stop systemd-networkd.service
# defaults to yes (both the global and per-link settings are yes)
assert_in 'yes' "$(resolvectl mdns hoge)"
assert_in 'yes' "$(resolvectl llmnr hoge)"
# set per-link setting
resolvectl mdns hoge yes
resolvectl llmnr hoge yes
assert_in 'yes' "$(resolvectl mdns hoge)"
assert_in 'yes' "$(resolvectl llmnr hoge)"
resolvectl mdns hoge resolve
resolvectl llmnr hoge resolve
assert_in 'resolve' "$(resolvectl mdns hoge)"
assert_in 'resolve' "$(resolvectl llmnr hoge)"
resolvectl mdns hoge no
resolvectl llmnr hoge no
assert_in 'no' "$(resolvectl mdns hoge)"
assert_in 'no' "$(resolvectl llmnr hoge)"
# downgrade global setting to resolve
{
    echo "[Resolve]"
    echo "MulticastDNS=resolve"
    echo "LLMNR=resolve"
} >/run/systemd/resolved.conf.d/mdns-llmnr.conf
restart_resolved
# set per-link setting
resolvectl mdns hoge yes
resolvectl llmnr hoge yes
assert_in 'resolve' "$(resolvectl mdns hoge)"
assert_in 'resolve' "$(resolvectl llmnr hoge)"
resolvectl mdns hoge resolve
resolvectl llmnr hoge resolve
assert_in 'resolve' "$(resolvectl mdns hoge)"
assert_in 'resolve' "$(resolvectl llmnr hoge)"
resolvectl mdns hoge no
resolvectl llmnr hoge no
assert_in 'no' "$(resolvectl mdns hoge)"
assert_in 'no' "$(resolvectl llmnr hoge)"
# downgrade global setting to no
{
    echo "[Resolve]"
    echo "MulticastDNS=no"
    echo "LLMNR=no"
} >/run/systemd/resolved.conf.d/mdns-llmnr.conf
restart_resolved
# set per-link setting
resolvectl mdns hoge yes
resolvectl llmnr hoge yes
assert_in 'no' "$(resolvectl mdns hoge)"
assert_in 'no' "$(resolvectl llmnr hoge)"
resolvectl mdns hoge resolve
resolvectl llmnr hoge resolve
assert_in 'no' "$(resolvectl mdns hoge)"
assert_in 'no' "$(resolvectl llmnr hoge)"
resolvectl mdns hoge no
resolvectl llmnr hoge no
assert_in 'no' "$(resolvectl mdns hoge)"
assert_in 'no' "$(resolvectl llmnr hoge)"

# Cleanup
rm -f /run/systemd/resolved.conf.d/mdns-llmnr.conf
ip link del hoge
ip link del hoge.foo

### SETUP ###
# Configure network
hostnamectl hostname ns1.unsigned.test
cat >>/etc/hosts <<EOF
10.0.0.1               ns1.unsigned.test
fd00:dead:beef:cafe::1 ns1.unsigned.test

127.128.0.5     localhost5 localhost5.localdomain localhost5.localdomain4 localhost.localdomain5 localhost5.localdomain5
EOF

mkdir -p /etc/systemd/network
cat >/etc/systemd/network/10-dns0.netdev <<EOF
[NetDev]
Name=dns0
Kind=dummy
EOF
cat >/etc/systemd/network/10-dns0.network <<EOF
[Match]
Name=dns0

[Network]
Address=10.0.0.1/24
Address=fd00:dead:beef:cafe::1/64
DNSSEC=allow-downgrade
DNS=10.0.0.1
DNS=fd00:dead:beef:cafe::1
EOF

DNS_ADDRESSES=(
    "10.0.0.1"
    "fd00:dead:beef:cafe::1"
)

mkdir -p /run/systemd/resolved.conf.d
{
    echo "[Resolve]"
    echo "FallbackDNS="
    echo "DNSSEC=allow-downgrade"
    echo "DNSOverTLS=opportunistic"
} >/run/systemd/resolved.conf.d/test.conf
ln -svf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
# Override the default NTA list, which turns off DNSSEC validation for (among
# others) the test. domain
mkdir -p "/etc/dnssec-trust-anchors.d/"
echo local >/etc/dnssec-trust-anchors.d/local.negative

# Sign the root zone
keymgr . generate algorithm=ECDSAP256SHA256 ksk=yes zsk=yes
# Create a trust anchor for resolved with our root zone
keymgr . ds | sed 's/ DS/ IN DS/g' >/etc/dnssec-trust-anchors.d/root.positive
# Create a bind-compatible trust anchor (for delv)
# Note: the trust-anchors directive is relatively new, so use the original
#       managed-keys one until it's widespread enough
{
    echo 'managed-keys {'
    keymgr . dnskey | sed -r 's/^\. DNSKEY ([0-9]+ [0-9]+ [0-9]+) (.+)$/. static-key \1 "\2";/g'
    echo '};'
} >/etc/bind.keys
# Create an /etc/bind/bind.keys symlink, which is used by delv on Ubuntu
mkdir -p /etc/bind
ln -svf /etc/bind.keys /etc/bind/bind.keys

# Start the services
systemctl unmask systemd-networkd
systemctl start systemd-networkd
restart_resolved
# Create knot's runtime dir, since from certain version it's provided only by
# the package and not created by tmpfiles/systemd
if [[ ! -d /run/knot ]]; then
    mkdir -p /run/knot
    chown -R knot:knot /run/knot
fi
systemctl start knot
# Wait a bit for the keys to propagate
sleep 4

networkctl status
resolvectl status
resolvectl log-level debug

# Start monitoring queries
systemd-run -u resolvectl-monitor.service -p Type=notify resolvectl monitor
systemd-run -u resolvectl-monitor-json.service -p Type=notify resolvectl monitor --json=short

# Check if all the zones are valid (zone-check always returns 0, so let's check
# if it produces any errors/warnings)
run knotc zone-check
[[ ! -s "$RUN_OUT" ]]
# We need to manually propagate the DS records of onlinesign.test. to the parent
# zone, since they're generated online
knotc zone-begin test.
if knotc zone-get test. onlinesign.test. ds | grep .; then
    # Drop any old DS records, if present (e.g. on test re-run)
    knotc zone-unset test. onlinesign.test. ds
fi
# Propagate the new DS records
while read -ra line; do
    knotc zone-set test. "${line[0]}" 600 "${line[@]:1}"
done < <(keymgr onlinesign.test. ds)
knotc zone-commit test.

knotc reload

### SETUP END ###

: "--- nss-resolve/nss-myhostname tests"
# Sanity check
TIMESTAMP=$(date '+%F %T')
# Issue: https://github.com/systemd/systemd/issues/23951
# With IPv6 enabled
run getent -s resolve hosts ns1.unsigned.test
grep -qE "^fd00:dead:beef:cafe::1\s+ns1\.unsigned\.test" "$RUN_OUT"
monitor_check_rr "$TIMESTAMP" "ns1.unsigned.test IN AAAA fd00:dead:beef:cafe::1"
# With IPv6 disabled
# Issue: https://github.com/systemd/systemd/issues/23951
# FIXME
#disable_ipv6
#run getent -s resolve hosts ns1.unsigned.test
#grep -qE "^10\.0\.0\.1\s+ns1\.unsigned\.test" "$RUN_OUT"
#monitor_check_rr "$TIMESTAMP" "ns1.unsigned.test IN A 10.0.0.1"
enable_ipv6

# Issue: https://github.com/systemd/systemd/issues/18812
# PR: https://github.com/systemd/systemd/pull/18896
# Follow-up issue: https://github.com/systemd/systemd/issues/23152
# Follow-up PR: https://github.com/systemd/systemd/pull/23161
# With IPv6 enabled
run getent -s resolve hosts localhost
grep -qE "^::1\s+localhost" "$RUN_OUT"
run getent -s myhostname hosts localhost
grep -qE "^::1\s+localhost" "$RUN_OUT"
# With IPv6 disabled
disable_ipv6
run getent -s resolve hosts localhost
grep -qE "^127\.0\.0\.1\s+localhost" "$RUN_OUT"
run getent -s myhostname hosts localhost
grep -qE "^127\.0\.0\.1\s+localhost" "$RUN_OUT"
enable_ipv6

# Issue: https://github.com/systemd/systemd/issues/25088
run getent -s resolve hosts 127.128.0.5
grep -qEx '127\.128\.0\.5\s+localhost5(\s+localhost5?\.localdomain[45]?){4}' "$RUN_OUT"
[ "$(wc -l <"$RUN_OUT")" -eq 1 ]

# Issue: https://github.com/systemd/systemd/issues/20158
run dig +noall +answer +additional localhost5.
grep -qEx 'localhost5\.\s+0\s+IN\s+A\s+127\.128\.0\.5' "$RUN_OUT"
[ "$(wc -l <"$RUN_OUT")" -eq 1 ]
run dig +noall +answer +additional localhost5.localdomain4.
grep -qEx 'localhost5\.localdomain4\.\s+0\s+IN\s+CNAME\s+localhost5\.' "$RUN_OUT"
grep -qEx 'localhost5\.\s+0\s+IN\s+A\s+127\.128\.0\.5' "$RUN_OUT"
[ "$(wc -l <"$RUN_OUT")" -eq 2 ]

: "--- Basic resolved tests ---"
# Issue: https://github.com/systemd/systemd/issues/22229
# PR: https://github.com/systemd/systemd/pull/22231
FILTERED_NAMES=(
    "0.in-addr.arpa"
    "255.255.255.255.in-addr.arpa"
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
    "hello.invalid"
    "hello.alt"
)

for name in "${FILTERED_NAMES[@]}"; do
    (! run host "$name")
    grep -qF "NXDOMAIN" "$RUN_OUT"
done

# Follow-up
# Issue: https://github.com/systemd/systemd/issues/22401
# PR: https://github.com/systemd/systemd/pull/22414
run dig +noall +authority +comments SRV .
grep -qF "status: NOERROR" "$RUN_OUT"
grep -qE "IN\s+SOA\s+ns1\.unsigned\.test\." "$RUN_OUT"


: "--- ZONE: unsigned.test. ---"
run dig @ns1.unsigned.test +short unsigned.test A unsigned.test AAAA
grep -qF "10.0.0.101" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::101" "$RUN_OUT"
run resolvectl query unsigned.test
grep -qF "10.0.0.10" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::101" "$RUN_OUT"
grep -qF "authenticated: no" "$RUN_OUT"
run dig @ns1.unsigned.test +short MX unsigned.test
grep -qF "15 mail.unsigned.test." "$RUN_OUT"
run resolvectl query --legend=no -t MX unsigned.test
grep -qF "unsigned.test IN MX 15 mail.unsigned.test" "$RUN_OUT"


: "--- ZONE: signed.test (static DNSSEC) ---"
# Check the trust chain (with and without systemd-resolved in between
# Issue: https://github.com/systemd/systemd/issues/22002
# PR: https://github.com/systemd/systemd/pull/23289
run_delv @ns1.unsigned.test signed.test
grep -qF "; fully validated" "$RUN_OUT"
run_delv signed.test
grep -qF "; fully validated" "$RUN_OUT"

for addr in "${DNS_ADDRESSES[@]}"; do
    run_delv "@$addr" -t A mail.signed.test
    grep -qF "; fully validated" "$RUN_OUT"
    run_delv "@$addr" -t AAAA mail.signed.test
    grep -qF "; fully validated" "$RUN_OUT"
done
run resolvectl query mail.signed.test
grep -qF "10.0.0.11" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::11" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"

run dig +short signed.test
grep -qF "10.0.0.10" "$RUN_OUT"
run resolvectl query signed.test
grep -qF "signed.test: 10.0.0.10" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"
run dig @ns1.unsigned.test +short MX signed.test
grep -qF "10 mail.signed.test." "$RUN_OUT"
run resolvectl query --legend=no -t MX signed.test
grep -qF "signed.test IN MX 10 mail.signed.test" "$RUN_OUT"
# Check a non-existent domain
run dig +dnssec this.does.not.exist.signed.test
grep -qF "status: NXDOMAIN" "$RUN_OUT"
# Check a wildcard record
run resolvectl query -t TXT this.should.be.authenticated.wild.signed.test
grep -qF 'this.should.be.authenticated.wild.signed.test IN TXT "this is a wildcard"' "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"
# Check SRV support
run resolvectl service _mysvc._tcp signed.test
grep -qF "myservice.signed.test:1234" "$RUN_OUT"
grep -qF "10.0.0.20" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::17" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"
(! run resolvectl service _invalidsvc._udp signed.test)
grep -qE "invalidservice\.signed\.test' not found" "$RUN_OUT"
run resolvectl service _untrustedsvc._udp signed.test
grep -qF "myservice.untrusted.test:1111" "$RUN_OUT"
grep -qF "10.0.0.123" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::123" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"
# Check OPENPGPKEY support
run_delv -t OPENPGPKEY 5a786cdc59c161cdafd818143705026636962198c66ed4c5b3da321e._openpgpkey.signed.test
grep -qF "; fully validated" "$RUN_OUT"
run resolvectl openpgp mr.smith@signed.test
grep -qF "5a786cdc59c161cdafd818143705026636962198c66ed4c5b3da321e._openpgpkey.signed.test" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"

# DNSSEC validation with multiple records of the same type for the same name
# Issue: https://github.com/systemd/systemd/issues/22002
# PR: https://github.com/systemd/systemd/pull/23289
check_domain() {
    local domain="${1:?}"
    local record="${2:?}"
    local message="${3:?}"
    local addr

    for addr in "${DNS_ADDRESSES[@]}"; do
        run_delv "@$addr" -t "$record" "$domain"
        grep -qF "$message" "$RUN_OUT"
    done

    run_delv -t "$record" "$domain"
    grep -qF "$message" "$RUN_OUT"

    run resolvectl query "$domain"
    grep -qF "authenticated: yes" "$RUN_OUT"
}

check_domain "dupe.signed.test"       "A"    "; fully validated"
check_domain "dupe.signed.test"       "AAAA" "; negative response, fully validated"
check_domain "dupe-ipv6.signed.test"  "AAAA" "; fully validated"
check_domain "dupe-ipv6.signed.test"  "A"    "; negative response, fully validated"
check_domain "dupe-mixed.signed.test" "A"    "; fully validated"
check_domain "dupe-mixed.signed.test" "AAAA" "; fully validated"

# Test resolution of CNAME chains
TIMESTAMP=$(date '+%F %T')
run resolvectl query -t A cname-chain.signed.test
grep -qF "follow14.final.signed.test IN A 10.0.0.14" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"

monitor_check_rr "$TIMESTAMP" "follow10.so.close.signed.test IN CNAME follow11.yet.so.far.signed.test"
monitor_check_rr "$TIMESTAMP" "follow11.yet.so.far.signed.test IN CNAME follow12.getting.hot.signed.test"
monitor_check_rr "$TIMESTAMP" "follow12.getting.hot.signed.test IN CNAME follow13.almost.final.signed.test"
monitor_check_rr "$TIMESTAMP" "follow13.almost.final.signed.test IN CNAME follow14.final.signed.test"
monitor_check_rr "$TIMESTAMP" "follow14.final.signed.test IN A 10.0.0.14"

# Non-existing RR + CNAME chain
run dig +dnssec AAAA cname-chain.signed.test
grep -qF "status: NOERROR" "$RUN_OUT"
grep -qE "^follow14\.final\.signed\.test\..+IN\s+NSEC\s+" "$RUN_OUT"


: "--- ZONE: onlinesign.test (dynamic DNSSEC) ---"
# Check the trust chain (with and without systemd-resolved in between
# Issue: https://github.com/systemd/systemd/issues/22002
# PR: https://github.com/systemd/systemd/pull/23289
run_delv @ns1.unsigned.test sub.onlinesign.test
grep -qF "; fully validated" "$RUN_OUT"
run_delv sub.onlinesign.test
grep -qF "; fully validated" "$RUN_OUT"

run dig +short sub.onlinesign.test
grep -qF "10.0.0.133" "$RUN_OUT"
run resolvectl query sub.onlinesign.test
grep -qF "sub.onlinesign.test: 10.0.0.133" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"
run dig @ns1.unsigned.test +short TXT onlinesign.test
grep -qF '"hello from onlinesign"' "$RUN_OUT"
run resolvectl query --legend=no -t TXT onlinesign.test
grep -qF 'onlinesign.test IN TXT "hello from onlinesign"' "$RUN_OUT"

for addr in "${DNS_ADDRESSES[@]}"; do
    run_delv "@$addr" -t A dual.onlinesign.test
    grep -qF "10.0.0.135" "$RUN_OUT"
    run_delv "@$addr" -t AAAA dual.onlinesign.test
    grep -qF "fd00:dead:beef:cafe::135" "$RUN_OUT"
    run_delv "@$addr" -t ANY ipv6.onlinesign.test
    grep -qF "fd00:dead:beef:cafe::136" "$RUN_OUT"
done
run resolvectl query dual.onlinesign.test
grep -qF "10.0.0.135" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::135" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"
run resolvectl query ipv6.onlinesign.test
grep -qF "fd00:dead:beef:cafe::136" "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"

# Check a non-existent domain
# Note: mod-onlinesign utilizes Minimally Covering NSEC Records, hence the
#       different response than with "standard" DNSSEC
run dig +dnssec this.does.not.exist.onlinesign.test
grep -qF "status: NOERROR" "$RUN_OUT"
grep -qF "NSEC \\000.this.does.not.exist.onlinesign.test." "$RUN_OUT"
# Check a wildcard record
run resolvectl query -t TXT this.should.be.authenticated.wild.onlinesign.test
grep -qF 'this.should.be.authenticated.wild.onlinesign.test IN TXT "this is an onlinesign wildcard"' "$RUN_OUT"
grep -qF "authenticated: yes" "$RUN_OUT"

# Resolve via dbus method
TIMESTAMP=$(date '+%F %T')
run busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResolveHostname 'isit' 0 secondsub.onlinesign.test 0 0
grep -qF '10 0 0 134 "secondsub.onlinesign.test"' "$RUN_OUT"
monitor_check_rr "$TIMESTAMP" "secondsub.onlinesign.test IN A 10.0.0.134"


: "--- ZONE: untrusted.test (DNSSEC without propagated DS records) ---"
# Issue: https://github.com/systemd/systemd/issues/23955
# FIXME
resolvectl flush-caches
#run dig +short untrusted.test A untrusted.test AAAA
#grep -qF "10.0.0.121" "$RUN_OUT"
#grep -qF "fd00:dead:beef:cafe::121" "$RUN_OUT"
run resolvectl query untrusted.test
grep -qF "untrusted.test:" "$RUN_OUT"
grep -qF "10.0.0.121" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::121" "$RUN_OUT"
grep -qF "authenticated: no" "$RUN_OUT"
run resolvectl service _mysvc._tcp untrusted.test
grep -qF "myservice.untrusted.test:1234" "$RUN_OUT"
grep -qF "10.0.0.123" "$RUN_OUT"
grep -qF "fd00:dead:beef:cafe::123" "$RUN_OUT"

# Issue: https://github.com/systemd/systemd/issues/19472
# 1) Query for a non-existing RR should return NOERROR + NSEC (?), not NXDOMAIN
# FIXME: re-enable once the issue is resolved
#run dig +dnssec AAAA untrusted.test
#grep -qF "status: NOERROR" "$RUN_OUT"
#grep -qE "^untrusted\.test\..+IN\s+NSEC\s+" "$RUN_OUT"
## 2) Query for a non-existing name should return NXDOMAIN, not SERVFAIL
#run dig +dnssec this.does.not.exist.untrusted.test
#grep -qF "status: NXDOMAIN" "$RUN_OUT"

### Test resolvectl show-cache
run resolvectl show-cache
run resolvectl show-cache --json=short
run resolvectl show-cache --json=pretty

# Issue: https://github.com/systemd/systemd/issues/29580 (part #1)
dig @127.0.0.54 signed.test

systemctl stop resolvectl-monitor.service
systemctl stop resolvectl-monitor-json.service

# Issue: https://github.com/systemd/systemd/issues/29580 (part #2)
#
# Check for any warnings regarding malformed messages
(! journalctl -u resolvectl-monitor.service -u reseolvectl-monitor-json.service -p warning --grep malformed)
# Verify that all queries recorded by `resolvectl monitor --json` produced a valid JSON
# with expected fields
journalctl -p info -o cat _SYSTEMD_UNIT="resolvectl-monitor-json.service" | while read -r line; do
    # Check that both "question" and "answer" fields are arrays
    #
    # The expression is slightly more complicated due to the fact that the "answer" field is optional,
    # so we need to select it only if it's present, otherwise the type == "array" check would fail
    echo "$line" | jq -e '[. | .question, (select(has("answer")) | .answer) | type == "array"] | all'
done

# Test serve stale feature and NFTSet= if nftables is installed
if command -v nft >/dev/null; then
    ### Test without serve stale feature ###
    NFT_FILTER_NAME=dns_port_filter

    drop_dns_outbound_traffic() {
        nft add table inet $NFT_FILTER_NAME
        nft add chain inet $NFT_FILTER_NAME output \{ type filter hook output priority 0 \; \}
        nft add rule inet $NFT_FILTER_NAME output ip daddr 10.0.0.1 udp dport 53 drop
        nft add rule inet $NFT_FILTER_NAME output ip daddr 10.0.0.1 tcp dport 53 drop
        nft add rule inet $NFT_FILTER_NAME output ip6 daddr fd00:dead:beef:cafe::1 udp dport 53 drop
        nft add rule inet $NFT_FILTER_NAME output ip6 daddr fd00:dead:beef:cafe::1 tcp dport 53 drop
    }

    run dig stale1.unsigned.test -t A
    grep -qE "NOERROR" "$RUN_OUT"
    sleep 2
    drop_dns_outbound_traffic
    set +e
    run dig stale1.unsigned.test -t A
    set -eux
    grep -qE "no servers could be reached" "$RUN_OUT"
    nft flush ruleset

    ### Test TIMEOUT with serve stale feature ###

    mkdir -p /run/systemd/resolved.conf.d
    {
        echo "[Resolve]"
        echo "StaleRetentionSec=1d"
    } >/run/systemd/resolved.conf.d/test.conf
    ln -svf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    restart_resolved

    run dig stale1.unsigned.test -t A
    grep -qE "NOERROR" "$RUN_OUT"
    sleep 2
    drop_dns_outbound_traffic
    run dig stale1.unsigned.test -t A
    grep -qE "NOERROR" "$RUN_OUT"
    grep -qE "10.0.0.112" "$RUN_OUT"

    nft flush ruleset

    ### Test NXDOMAIN with serve stale feature ###
    # NXDOMAIN response should replace the cache with NXDOMAIN response
    run dig stale1.unsigned.test -t A
    grep -qE "NOERROR" "$RUN_OUT"
    # Delete stale1 record from zone
    knotc zone-begin unsigned.test
    knotc zone-unset unsigned.test stale1 A
    knotc zone-commit unsigned.test
    knotc reload
    sleep 2
    run dig stale1.unsigned.test -t A
    grep -qE "NXDOMAIN" "$RUN_OUT"

    nft flush ruleset

    ### NFTSet= test
    nft add table inet sd_test
    nft add set inet sd_test c '{ type cgroupsv2; }'
    nft add set inet sd_test u '{ typeof meta skuid; }'
    nft add set inet sd_test g '{ typeof meta skgid; }'

    # service
    systemd-run --unit test-nft.service --service-type=exec -p DynamicUser=yes \
                -p 'NFTSet=cgroup:inet:sd_test:c user:inet:sd_test:u group:inet:sd_test:g' sleep 10000
    run nft list set inet sd_test c
    grep -qF "test-nft.service" "$RUN_OUT"
    uid=$(getent passwd test-nft | cut -d':' -f3)
    run nft list set inet sd_test u
    grep -qF "$uid" "$RUN_OUT"
    gid=$(getent passwd test-nft | cut -d':' -f4)
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
        echo "ExecStart=/usr/bin/sleep 10000"
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
else
    echo "nftables is not installed. Skipped serve stale feature and NFTSet= tests."
fi

### Test resolvectl show-server-state ###
run resolvectl show-server-state
grep -qF "10.0.0.1" "$RUN_OUT"
grep -qF "Interface" "$RUN_OUT"

run resolvectl show-server-state --json=short
grep -qF "10.0.0.1" "$RUN_OUT"
grep -qF "Interface" "$RUN_OUT"

run resolvectl show-server-state --json=pretty
grep -qF "10.0.0.1" "$RUN_OUT"
grep -qF "Interface" "$RUN_OUT"

### Test resolvectl statistics ###
run resolvectl statistics
grep -qF "Transactions" "$RUN_OUT"
grep -qF "Cache" "$RUN_OUT"
grep -qF "Failure Transactions" "$RUN_OUT"
grep -qF "DNSSEC Verdicts" "$RUN_OUT"

run resolvectl statistics --json=short
grep -qF "transactions" "$RUN_OUT"
grep -qF "cache" "$RUN_OUT"
grep -qF "dnssec" "$RUN_OUT"

run resolvectl statistics --json=pretty
grep -qF "transactions" "$RUN_OUT"
grep -qF "cache" "$RUN_OUT"
grep -qF "dnssec" "$RUN_OUT"

### Test resolvectl reset-statistics ###
run resolvectl reset-statistics

run resolvectl reset-statistics --json=pretty

run resolvectl reset-statistics --json=short

# Check if resolved exits cleanly.
restart_resolved

touch /testok
