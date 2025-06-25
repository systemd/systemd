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

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# We need at least Knot 3.0 which support (among others) the ds-push directive
if ! knotc -c /usr/lib/systemd/tests/testdata/knot-data/knot.conf conf-check; then
    echo "This test requires at least Knot 3.0. skipping..." | tee --append /skipped
    exit 77
fi

if ! command -v resolvectl >/dev/null || ! command -v networkctl >/dev/null; then
    echo "resolved/networkd not found, skipping..." | tee --append /skipped
    exit 77
fi

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

setup() {
    : "SETUP BEGIN"

    : "Setup - Configure network"
    hostnamectl hostname ns1.unsigned.test
    cat >>/etc/hosts <<EOF
10.0.0.1               ns1.unsigned.test
fd00:dead:beef:cafe::1 ns1.unsigned.test

127.128.0.5     localhost5 localhost5.localdomain localhost5.localdomain4 localhost.localdomain5 localhost5.localdomain5
EOF

    mkdir -p /run/systemd/network
    cat >/run/systemd/network/10-dns0.netdev <<EOF
[NetDev]
Name=dns0
Kind=dummy
EOF
    cat >/run/systemd/network/10-dns0.network <<EOF
[Match]
Name=dns0

[Network]
IPv6AcceptRA=no
Address=10.0.0.1/24
Address=fd00:dead:beef:cafe::1/64
DNSSEC=allow-downgrade
DNS=10.0.0.1
DNS=fd00:dead:beef:cafe::1
EOF
    cat >/run/systemd/network/10-dns1.netdev <<EOF
[NetDev]
Name=dns1
Kind=dummy
EOF
    cat >/run/systemd/network/10-dns1.network <<EOF
[Match]
Name=dns1

[Network]
IPv6AcceptRA=no
Address=10.99.0.1/24
DNSSEC=no
EOF
    systemctl edit --stdin --full --runtime --force "resolved-dummy-server.service" <<EOF
[Service]
Type=notify
Environment=SYSTEMD_LOG_LEVEL=debug
ExecStart=/usr/lib/systemd/tests/unit-tests/manual/test-resolved-dummy-server 10.99.0.1:53
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

    # Copy over our knot configuration
    mkdir -p /var/lib/knot/zones/ /etc/knot/
    cp -rfv /usr/lib/systemd/tests/testdata/knot-data/zones/* /var/lib/knot/zones/
    cp -fv /usr/lib/systemd/tests/testdata/knot-data/knot.conf /etc/knot/knot.conf
    chgrp -R knot /etc/knot/ /var/lib/knot/
    chmod -R ug+rwX /var/lib/knot/
    chmod -R g+r /etc/knot/

    : "Setup - Sign the root zone"
    keymgr . generate algorithm=ECDSAP256SHA256 ksk=yes zsk=yes
    # Create a trust anchor for resolved with our root zone
    keymgr . ds | sed 's/ DS/ IN DS/g' >/etc/dnssec-trust-anchors.d/root.positive
    # Create a bind-compatible trust anchor (for delv)
    # Note: managed-keys was removed in version 9.21, use the newer trust-anchors directive
    {
        if systemd-analyze compare-versions "$(delv -v | awk '{print $2}')" ge 9.21; then
            echo 'trust-anchors {'
        else
            echo 'managed-keys {'
        fi
        keymgr . dnskey | sed -r 's/^\. DNSKEY ([0-9]+ [0-9]+ [0-9]+) (.+)$/. static-key \1 "\2";/g'
        echo '};'
    } >/etc/bind.keys
    # Create an /etc/bind/bind.keys symlink, which is used by delv on Ubuntu
    mkdir -p /etc/bind
    ln -svf /etc/bind.keys /etc/bind/bind.keys

    # Start the services
    systemctl unmask systemd-networkd
    systemctl restart systemd-networkd
    /usr/lib/systemd/systemd-networkd-wait-online --interface=dns1:routable --timeout=60
    systemctl reload systemd-resolved
    systemctl start resolved-dummy-server

    # Create knot's runtime dir, since from certain version it's provided only by
    # the package and not created by tmpfiles/systemd
    if [[ ! -d /run/knot ]]; then
        mkdir -p /run/knot
        chown -R knot:knot /run/knot
    fi
    systemctl start knot
    # Wait a bit for the keys to propagate
    sleep 4

    systemctl status resolved-dummy-server
    networkctl status
    resolvectl status
    resolvectl log-level debug

    : "Setup - Start monitoring queries"
    systemd-run -u resolvectl-monitor.service -p Type=notify resolvectl monitor
    systemd-run -u resolvectl-monitor-json.service -p Type=notify resolvectl monitor --json=short

    : "Setup - Check if all the zones are valid"
    # FIXME: knot, unfortunately, incorrectly complains about missing zone files for zones
    #        that are forwarded using the `dnsproxy` module. Until the issue is resolved,
    #        let's fall back to pre-processing the `zone-check` output a bit before checking it
    #
    # See: https://gitlab.nic.cz/knot/knot-dns/-/issues/913
    run knotc zone-check || :
    sed -i '/forwarded.test./d' "$RUN_OUT"
    [[ ! -s "$RUN_OUT" ]]
    # We need to manually propagate the DS records of onlinesign.test. to the parent
    # zone, since they're generated online
    knotc zone-begin test.
    if knotc zone-get test. onlinesign.test. ds | grep .; then
        # Drop any old DS records, if present (e.g. on test re-run)
        knotc zone-unset test. onlinesign.test. ds
    fi

    : "Setup - Propagate the new DS records"
    while read -ra line; do
        knotc zone-set test. "${line[0]}" 600 "${line[@]:1}"
    done < <(keymgr onlinesign.test. ds)
    knotc zone-commit test.

    knotc reload
    sleep 2

    : "SETUP END"
}

# Test for resolvectl, resolvconf
manual_testcase_01_resolvectl() {
    ip link add hoge type dummy
    ip link add hoge.foo type dummy

    # Cleanup
    # shellcheck disable=SC2317
    cleanup() {
        rm -f /run/systemd/resolved.conf.d/mdns-llmnr.conf
        ip link del hoge
        ip link del hoge.foo
    }

    trap cleanup RETURN

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

    # DNS servers
    echo nameserver 10.0.2.1 10.0.2.2 | "$RESOLVCONF" -a hoge
    echo nameserver 10.0.2.3 10.0.2.4 | "$RESOLVCONF" -a hoge.foo
    assert_in '10.0.2.1 10.0.2.2' "$(resolvectl dns hoge)"
    assert_in '10.0.2.3 10.0.2.4' "$(resolvectl dns hoge.foo)"
    echo nameserver 10.0.3.1 10.0.3.2 | "$RESOLVCONF" -a hoge.inet.ipsec.192.168.35
    echo nameserver 10.0.3.3 10.0.3.4 | "$RESOLVCONF" -a hoge.foo.dhcp
    assert_in '10.0.3.1 10.0.3.2' "$(resolvectl dns hoge)"
    assert_in '10.0.3.3 10.0.3.4' "$(resolvectl dns hoge.foo)"

    # domain
    # without domain/search clears existing domain
    resolvectl domain hoge test-domain.example.com
    assert_in 'test-domain.example.com' "$(resolvectl domain hoge)"
    echo nameserver 10.0.2.1 10.0.2.2 | "$RESOLVCONF" -a hoge
    assert_not_in 'test-domain.example.com' "$(resolvectl domain hoge)"
    # cannot set domain without DNS servers
    (! echo domain test-domain.example.com | "$RESOLVCONF" -a hoge)
    # can set domain with DNS server(s)
    echo -e "nameserver 10.0.2.1 10.0.2.2\ndomain test-domain1.example.com test-domain2.example.com\nsearch test-search-domain.example.com" | "$RESOLVCONF" -a hoge
    assert_in 'test-domain1.example.com' "$(resolvectl domain hoge)"
    assert_in 'test-domain2.example.com' "$(resolvectl domain hoge)"
    assert_in 'test-search-domain.example.com' "$(resolvectl domain hoge)"

    # Tests for 'resolvconf -x'
    echo nameserver 10.0.2.1 | "$RESOLVCONF" -x -a hoge
    assert_in '~.' "$(resolvectl domain hoge)"
    resolvectl domain hoge "hoge.example.com"
    assert_in 'hoge.example.com' "$(resolvectl domain hoge)"
    assert_not_in '~.' "$(resolvectl domain hoge)"
    echo -e "nameserver 10.0.2.1\ndomain test-domain.example.com" | "$RESOLVCONF" -x -a hoge
    assert_in 'test-domain.example.com' "$(resolvectl domain hoge)"
    assert_in '~.' "$(resolvectl domain hoge)"

    # Tests for 'resolvconf -p'
    resolvectl default-route hoge yes
    assert_in 'yes' "$(resolvectl default-route hoge)"
    echo nameserver 10.0.3.3 10.0.3.4 | "$RESOLVCONF" -p -a hoge
    assert_in 'no' "$(resolvectl default-route hoge)"

    # Tests for 'resolvconf -d'
    resolvectl dns hoge 10.0.3.1 10.0.3.2
    resolvectl domain hoge test-domain.example.com
    "$RESOLVCONF" -d hoge
    assert_not_in '10.0.3.1' "$(resolvectl dns hoge)"
    assert_not_in '10.0.3.2' "$(resolvectl dns hoge)"
    assert_not_in 'test-domain.example.com' "$(resolvectl domain hoge)"

    # Tests for _localdnsstub and _localdnsproxy
    assert_in '127.0.0.53' "$(resolvectl query _localdnsstub)"
    assert_in '_localdnsstub' "$(resolvectl query 127.0.0.53)"
    assert_in '127.0.0.54' "$(resolvectl query _localdnsproxy)"
    assert_in '_localdnsproxy' "$(resolvectl query 127.0.0.54)"

    assert_in '127.0.0.53' "$(dig @127.0.0.53 _localdnsstub)"
    assert_in '_localdnsstub' "$(dig @127.0.0.53 -x 127.0.0.53)"
    assert_in '127.0.0.54' "$(dig @127.0.0.53 _localdnsproxy)"
    assert_in '_localdnsproxy' "$(dig @127.0.0.53 -x 127.0.0.54)"
}

# Tests for mDNS and LLMNR settings
manual_testcase_02_mdns_llmnr() {
    ip link add hoge type dummy
    ip link add hoge.foo type dummy

    # Cleanup
    cleanup() {
        rm -f /run/systemd/resolved.conf.d/mdns-llmnr.conf
        ip link del hoge
        ip link del hoge.foo
    }

    trap cleanup RETURN

    mkdir -p /run/systemd/resolved.conf.d
    {
        echo "[Resolve]"
        echo "MulticastDNS=no"
        echo "LLMNR=no"
    } >/run/systemd/resolved.conf.d/mdns-llmnr.conf
    restart_resolved
    # make sure networkd is not running.
    systemctl stop systemd-networkd.service
    assert_in 'no' "$(resolvectl mdns hoge)"
    assert_in 'no' "$(resolvectl llmnr hoge)"
    # Tests that reloading works
    {
        echo "[Resolve]"
        echo "MulticastDNS=yes"
        echo "LLMNR=yes"
    } >/run/systemd/resolved.conf.d/mdns-llmnr.conf
    systemctl reload systemd-resolved.service
    # defaults to yes (both the global and per-link settings are yes)
    assert_in 'yes' "$(resolvectl mdns hoge)"
    assert_in 'yes' "$(resolvectl llmnr hoge)"
    lsof -p "$(systemctl show --property MainPID --value systemd-resolved.service)" | grep -q ":mdns\|:5353"
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
    systemctl reload systemd-resolved.service
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
    systemctl reload systemd-resolved.service
    (! lsof -p "$(systemctl show --property MainPID --value systemd-resolved.service)" | grep -q ":mdns\|:5353")
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
}

testcase_03_23951() {
    : "--- nss-resolve/nss-myhostname tests"
    # Sanity check
    TIMESTAMP=$(date '+%F %T')
    # Issue: https://github.com/systemd/systemd/issues/23951
    # With IPv6 enabled
    run getent -s resolve ahosts ns1.unsigned.test
    grep -qE "^fd00:dead:beef:cafe::1\s+STREAM\s+ns1\.unsigned\.test" "$RUN_OUT"
    monitor_check_rr "$TIMESTAMP" "ns1.unsigned.test IN AAAA fd00:dead:beef:cafe::1"
    # With IPv6 disabled
    # Issue: https://github.com/systemd/systemd/issues/23951
    disable_ipv6
    run getent -s resolve ahosts ns1.unsigned.test
    grep -qE "^10\.0\.0\.1\s+STREAM\s+ns1\.unsigned\.test" "$RUN_OUT"
    (! grep -qE "fd00:dead:beef:cafe::1" "$RUN_OUT")
    monitor_check_rr "$TIMESTAMP" "ns1.unsigned.test IN A 10.0.0.1"
    enable_ipv6
}

testcase_04_18812() {
    # Issue: https://github.com/systemd/systemd/issues/18812
    # PR: https://github.com/systemd/systemd/pull/18896
    # Follow-up issue: https://github.com/systemd/systemd/issues/23152
    # Follow-up PR: https://github.com/systemd/systemd/pull/23161
    # With IPv6 enabled
    run getent -s resolve ahosts localhost
    grep -qE "^::1\s+STREAM\s+localhost" "$RUN_OUT"
    run getent -s myhostname ahosts localhost
    grep -qE "^::1\s+STREAM\s+localhost" "$RUN_OUT"
    # With IPv6 disabled
    disable_ipv6
    run getent -s resolve ahosts localhost
    grep -qE "^127\.0\.0\.1\s+STREAM\s+localhost" "$RUN_OUT"
    (! grep -qE "::1" "$RUN_OUT")
    run getent -s myhostname ahosts localhost
    grep -qE "^127\.0\.0\.1\s+STREAM\s+localhost" "$RUN_OUT"
    enable_ipv6
}

testcase_05_25088() {
    # Issue: https://github.com/systemd/systemd/issues/25088
    run getent -s resolve hosts 127.128.0.5
    grep -qEx '127\.128\.0\.5\s+localhost5(\s+localhost5?\.localdomain[45]?){4}' "$RUN_OUT"
    [ "$(wc -l <"$RUN_OUT")" -eq 1 ]
}

testcase_06_20158() {
    # Issue: https://github.com/systemd/systemd/issues/20158
    run dig +noall +answer +additional localhost5.
    grep -qEx 'localhost5\.\s+0\s+IN\s+A\s+127\.128\.0\.5' "$RUN_OUT"
    [ "$(wc -l <"$RUN_OUT")" -eq 1 ]
    run dig +noall +answer +additional localhost5.localdomain4.
    grep -qEx 'localhost5\.localdomain4\.\s+0\s+IN\s+CNAME\s+localhost5\.' "$RUN_OUT"
    grep -qEx 'localhost5\.\s+0\s+IN\s+A\s+127\.128\.0\.5' "$RUN_OUT"
    [ "$(wc -l <"$RUN_OUT")" -eq 2 ]
}

testcase_07_22229() {
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
}

testcase_08_resolved() {
    run resolvectl query -t SVCB svcb.test
    grep -qF 'alpn="dot"' "$RUN_OUT"
    grep -qF "ipv4hint=10.0.0.1" "$RUN_OUT"

    run resolvectl query -t HTTPS https.test
    grep -qF 'alpn="h2,h3"' "$RUN_OUT"

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
    run dig @ns1.unsigned.test +noall +comments unsigned.test CNAME
    grep -qF "status: NOERROR" "$RUN_OUT"

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

    run dig +nostats signed.test
    grep -qF "10.0.0.10" "$RUN_OUT"
    grep -q "flags:[^;]* ad" "$RUN_OUT"
    run dig +nostats +cd signed.test
    grep -qF "10.0.0.10" "$RUN_OUT"
    grep -q "flags:[^;]* cd" "$RUN_OUT"
    grep -qv "flags:[^;]* ad" "$RUN_OUT"
    run dig +nostats +do signed.test
    grep -qF "10.0.0.10" "$RUN_OUT"
    grep -q "flags:[^;]* ad" "$RUN_OUT"
    grep -qv "flags:[^;]* cd" "$RUN_OUT"
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

    # Test service resolve over Varlink
    run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService '{"name":"","type":"_mysvc._tcp","domain":"signed.test"}'
    grep -qF '"services":[{"priority":10,"weight":5,"port":1234,"hostname":"myservice.signed.test","canonicalName":"myservice.signed.test","addresses":[{"ifindex":' "$RUN_OUT"
    grep -qF '"family":10,"address":[253,0,222,173,190,239,202,254,0,0,0,0,0,0,0,23]' "$RUN_OUT"
    grep -qF '"family":2,"address":[10,0,0,20]' "$RUN_OUT"
    grep -qF '}]}],"txt":["This is TXT for myservice"],"canonical":{"name":null,"type":"_mysvc._tcp","domain":"signed.test"},"flags":' "$RUN_OUT"

    # without name
    run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService '{"type":"_mysvc._tcp","domain":"signed.test"}'
    # without txt (SD_RESOLVE_NO_TXT)
    run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService '{"type":"_mysvc._tcp","domain":"signed.test","flags":64}'
    (! grep -qF '"txt"' "$RUN_OUT")
    # without address (SD_RESOLVE_NO_ADDRESS)
    run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService '{"type":"_mysvc._tcp","domain":"signed.test","flags":128}'
    (! grep -qF '"addresses"' "$RUN_OUT")
    # without txt and address
    run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService '{"type":"_mysvc._tcp","domain":"signed.test","flags":192}'
    (! grep -qF '"txt"' "$RUN_OUT")
    (! grep -qF '"addresses"' "$RUN_OUT")

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
    # Check zone transfers (AXFR/IXFR)
    # Note: since resolved doesn't support zone transfers, let's just make sure it
    #       simply refuses such requests without choking on them
    # See: https://github.com/systemd/systemd/pull/30809#issuecomment-1880102804
    run dig @ns1.unsigned.test AXFR signed.test
    grep -qE "SOA\s+ns1.unsigned.test. root.unsigned.test." "$RUN_OUT"
    run dig AXFR signed.test
    grep -qF "; Transfer failed" "$RUN_OUT"
    run dig @ns1.unsigned.test IXFR=43 signed.test
    grep -qE "SOA\s+ns1.unsigned.test. root.unsigned.test." "$RUN_OUT"
    run dig IXFR=43 signed.test
    grep -qF "; Transfer failed" "$RUN_OUT"

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
    #run dig +dnssec AAAA cname-chain.signed.test
    #grep -qF "status: NOERROR" "$RUN_OUT"
    #grep -qE "^follow14\.final\.signed\.test\..+IN\s+NSEC\s+" "$RUN_OUT"


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

    : "--- ZONE: forwarded.test (queries forwarded to our dummy test server) ---"
    JOURNAL_CURSOR="$(mktemp)"
    journalctl -n0 -q --cursor-file="$JOURNAL_CURSOR"

    # See "test-resolved-dummy-server.c" for the server part
    (! run resolvectl query nope.forwarded.test)
    grep -qF "nope.forwarded.test" "$RUN_OUT"
    grep -qF "not found" "$RUN_OUT"

    # SERVFAIL + EDE code 6: DNSSEC Bogus
    (! run resolvectl query edns-bogus-dnssec.forwarded.test)
    grep -qE "^edns-bogus-dnssec.forwarded.test:.+: upstream-failure \(DNSSEC Bogus\)" "$RUN_OUT"
    # Same thing, but over Varlink
    (! run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname '{"name" : "edns-bogus-dnssec.forwarded.test"}')
    grep -qF "io.systemd.Resolve.DNSSECValidationFailed" "$RUN_OUT"
    grep -qF '{"result":"upstream-failure","extendedDNSErrorCode":6}' "$RUN_OUT"
    journalctl --sync
    journalctl -u systemd-resolved.service --cursor-file="$JOURNAL_CURSOR" --grep "Server returned error: SERVFAIL \(DNSSEC Bogus\). Lookup failed."

    # SERVFAIL + EDE code 16: Censored + extra text
    (! run resolvectl query edns-extra-text.forwarded.test)
    grep -qE "^edns-extra-text.forwarded.test.+: SERVFAIL \(Censored: Nothing to see here!\)" "$RUN_OUT"
    (! run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname '{"name" : "edns-extra-text.forwarded.test"}')
    grep -qF "io.systemd.Resolve.DNSError" "$RUN_OUT"
    grep -qF '{"rcode":2,"extendedDNSErrorCode":16,"extendedDNSErrorMessage":"Nothing to see here!"}' "$RUN_OUT"
    journalctl --sync
    journalctl -u systemd-resolved.service --cursor-file="$JOURNAL_CURSOR" --grep "Server returned error: SERVFAIL \(Censored: Nothing to see here!\)"

    # SERVFAIL + EDE code 0: Other + extra text
    (! run resolvectl query edns-code-zero.forwarded.test)
    grep -qE "^edns-code-zero.forwarded.test:.+: SERVFAIL \(Other: 🐱\)" "$RUN_OUT"
    (! run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname '{"name" : "edns-code-zero.forwarded.test"}')
    grep -qF "io.systemd.Resolve.DNSError" "$RUN_OUT"
    grep -qF '{"rcode":2,"extendedDNSErrorCode":0,"extendedDNSErrorMessage":"🐱"}' "$RUN_OUT"
    journalctl --sync
    journalctl -u systemd-resolved.service --cursor-file="$JOURNAL_CURSOR" --grep "Server returned error: SERVFAIL \(Other: 🐱\)"

    # SERVFAIL + invalid EDE code
    (! run resolvectl query edns-invalid-code.forwarded.test)
    grep -qE "^edns-invalid-code.forwarded.test:.+: SERVFAIL \([0-9]+\)" "$RUN_OUT"
    (! run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname '{"name" : "edns-invalid-code.forwarded.test"}')
    grep -qF "io.systemd.Resolve.DNSError" "$RUN_OUT"
    grep -qE '{"rcode":2,"extendedDNSErrorCode":[0-9]+}' "$RUN_OUT"
    journalctl --sync
    journalctl -u systemd-resolved.service --cursor-file="$JOURNAL_CURSOR" --grep "Server returned error: SERVFAIL \(\d+\)"

    # SERVFAIL + invalid EDE code + extra text
    (! run resolvectl query edns-invalid-code-with-extra-text.forwarded.test)
    grep -qE '^edns-invalid-code-with-extra-text.forwarded.test:.+: SERVFAIL \([0-9]+: Hello \[#\]\$%~ World\)' "$RUN_OUT"
    (! run varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname '{"name" : "edns-invalid-code-with-extra-text.forwarded.test"}')
    grep -qF "io.systemd.Resolve.DNSError" "$RUN_OUT"
    grep -qE '{"rcode":2,"extendedDNSErrorCode":[0-9]+,"extendedDNSErrorMessage":"Hello \[#\]\$%~ World"}' "$RUN_OUT"
    journalctl --sync
    journalctl -u systemd-resolved.service --cursor-file="$JOURNAL_CURSOR" --grep "Server returned error: SERVFAIL \(\d+: Hello \[\#\]\\$%~ World\)"
}

testcase_09_resolvectl_showcache() {
    ### Test resolvectl show-cache
    run resolvectl show-cache
    run resolvectl show-cache --json=short
    run resolvectl show-cache --json=pretty
}

testcase_10_resolvectl_json() {
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
}

# Test serve stale feature and NFTSet= if nftables is installed
testcase_11_nft() {
    if ! command -v nft >/dev/null; then
        echo "nftables is not installed. Skipped serve stale feature and NFTSet= tests."
        return 0
    fi

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
    # Make sure we give sd-resolved enough time to timeout (5-10s) before giving up
    # See: https://github.com/systemd/systemd/issues/31639#issuecomment-2009152617
    run dig +tries=1 +timeout=15 stale1.unsigned.test -t A
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
    systemctl reload systemd-resolved.service

    run dig stale1.unsigned.test -t A
    grep -qE "NOERROR" "$RUN_OUT"
    sleep 2
    drop_dns_outbound_traffic
    # Make sure we give sd-resolved enough time to timeout (5-10s) and serve the stale data (see above)
    run dig +tries=1 +timeout=15 stale1.unsigned.test -t A
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
}

# Test resolvectl show-server-state
testcase_12_resolvectl2() {
    # Cleanup
    # shellcheck disable=SC2317
    cleanup() {
        rm -f /run/systemd/resolved.conf.d/reload.conf
        systemctl reload systemd-resolved.service
    }

    trap cleanup RETURN

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

    test "$(resolvectl --json=short query -t AAAA localhost)" == '{"key":{"class":1,"type":28,"name":"localhost"},"address":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]}'
    test "$(resolvectl --json=short query -t A localhost)" == '{"key":{"class":1,"type":1,"name":"localhost"},"address":[127,0,0,1]}'

    # Test ResolveRecord RR resolving via Varlink
    test "$(varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveRecord '{"name":"localhost","type":1}' --json=short | jq -rc 'del(.rrs | .[] | .ifindex)')" == '{"rrs":[{"rr":{"key":{"class":1,"type":1,"name":"localhost"},"address":[127,0,0,1]},"raw":"CWxvY2FsaG9zdAAAAQABAAAAAAAEfwAAAQ=="}],"flags":786945}'
    test "$(varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveRecord '{"name":"localhost","type":28}' --json=short | jq -rc 'del(.rrs | .[] | .ifindex)')" == '{"rrs":[{"rr":{"key":{"class":1,"type":28,"name":"localhost"},"address":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]},"raw":"CWxvY2FsaG9zdAAAHAABAAAAAAAQAAAAAAAAAAAAAAAAAAAAAQ=="}],"flags":786945}'

    # Ensure that reloading keeps the manually configured address
    {
        echo "[Resolve]"
        echo "DNS=8.8.8.8"
        echo "DNSStubListenerExtra=127.0.0.153"
    } >/run/systemd/resolved.conf.d/reload.conf
    resolvectl dns dns0 1.1.1.1
    systemctl reload systemd-resolved.service
    resolvectl status

    run resolvectl dns dns0
    grep -qF "1.1.1.1" "$RUN_OUT"

    run resolvectl dns
    grep -qF "8.8.8.8" "$RUN_OUT"

    run ss -4nl
    grep -qF '127.0.0.153' "$RUN_OUT"

    {
        echo "[Resolve]"
        echo "DNS=8.8.4.4"
        echo "DNSStubListenerExtra=127.0.0.154"
    } >/run/systemd/resolved.conf.d/reload.conf
    systemctl reload systemd-resolved.service
    resolvectl status

    run resolvectl dns dns0
    grep -qF "1.1.1.1" "$RUN_OUT"

    run resolvectl dns
    (! grep -qF "8.8.8.8" "$RUN_OUT")
    grep -qF "8.8.4.4" "$RUN_OUT"

    run ss -4nl
    (! grep -qF '127.0.0.153' "$RUN_OUT")
    grep -qF '127.0.0.154' "$RUN_OUT"

    # Check if resolved exits cleanly.
    restart_resolved
}

# PRE-SETUP
systemctl unmask systemd-resolved.service
systemctl enable --now systemd-resolved.service
systemctl service-log-level systemd-resolved.service debug

# Need to be run before SETUP, otherwise things will break
manual_testcase_01_resolvectl
manual_testcase_02_mdns_llmnr

# Run setup
setup

# Run tests
run_testcases

touch /testok
