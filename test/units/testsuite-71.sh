#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

restore_hostname() {
    if [[ -e /tmp/hostname.bak ]]; then
        mv /tmp/hostname.bak /etc/hostname
    else
        rm -f /etc/hostname
    fi
}

testcase_hostname() {
    local orig=

    if [[ -f /etc/hostname ]]; then
        cp /etc/hostname /tmp/hostname.bak
        orig=$(cat /etc/hostname)
    fi

    trap restore_hostname RETURN

    # should activate daemon and work
    if [[ -n "$orig" ]]; then
        assert_in "Static hostname: $orig" "$(hostnamectl)"
    fi
    assert_in "Kernel: $(uname -s) $(uname -r)" "$(hostnamectl)"

    # change hostname
    assert_rc 0 hostnamectl set-hostname testhost
    assert_eq "$(cat /etc/hostname)" "testhost"
    assert_in "Static hostname: testhost" "$(hostnamectl)"

    if [[ -n "$orig" ]]; then
        # reset to original
        assert_rc 0 hostnamectl set-hostname "$orig"
        assert_eq "$(cat /etc/hostname)" "$orig"
        assert_in "Static hostname: $orig" "$(hostnamectl)"
    fi
}

restore_machine_info() {
    if [[ -e /tmp/machine-info.bak ]]; then
        mv /tmp/machine-info.bak /etc/machine-info
    else
        rm -f /etc/machine-info
    fi
}

get_chassis() (
    # shellcheck source=/dev/null
    . /etc/machine-info

    echo "$CHASSIS"
)

stop_hostnamed() {
    systemctl stop systemd-hostnamed.service
    systemctl reset-failed systemd-hostnamed # reset trigger limit
}

testcase_chassis() {
    local i

    if [[ -f /etc/machine-info ]]; then
        cp /etc/machine-info /tmp/machine-info.bak
    fi

    trap restore_machine_info RETURN

    # Invalid chassis type is refused
    assert_rc 1 hostnamectl chassis hoge

    # Valid chassis types
    for i in vm container desktop laptop convertible server tablet handset watch embedded; do
        hostnamectl chassis "$i"
        assert_eq "$(hostnamectl chassis)" "$i"
        assert_eq "$(get_chassis)" "$i"
    done

    stop_hostnamed
    rm -f /etc/machine-info

    # fallback chassis type
    if systemd-detect-virt --quiet --container; then
        assert_eq "$(hostnamectl chassis)" container
    elif systemd-detect-virt --quiet --vm; then
        assert_eq "$(hostnamectl chassis)" vm
    fi
}

restore_sysfs_dmi() {
    umount /sys/class/dmi/id
    rm -rf /run/systemd/system/systemd-hostnamed.service.d
    systemctl daemon-reload
    stop_hostnamed
}

testcase_firmware_date() {
    # No DMI on s390x or ppc
    if [[ ! -d /sys/class/dmi/id ]]; then
        echo "/sys/class/dmi/id not found, skipping firmware date tests."
        return 0
    fi

    trap restore_sysfs_dmi RETURN

    # Ignore /sys being mounted as tmpfs
    mkdir -p /run/systemd/system/systemd-hostnamed.service.d/
    cat >/run/systemd/system/systemd-hostnamed.service.d/override.conf <<EOF
[Service]
Environment="SYSTEMD_DEVICE_VERIFY_SYSFS=0"
Environment="SYSTEMD_HOSTNAME_FORCE_DMI=1"
EOF
    systemctl daemon-reload

    mount -t tmpfs none /sys/class/dmi/id
    echo '1' >/sys/class/dmi/id/uevent

    echo '09/08/2000' >/sys/class/dmi/id/bios_date
    stop_hostnamed
    assert_in '2000-09-08' "$(hostnamectl)"

    echo '2022' >/sys/class/dmi/id/bios_date
    stop_hostnamed
    assert_not_in 'Firmware Date' "$(hostnamectl)"

    echo 'garbage' >/sys/class/dmi/id/bios_date
    stop_hostnamed
    assert_not_in 'Firmware Date' "$(hostnamectl)"
}

testcase_nss-myhostname() {
    local database host i

    HOSTNAME="$(hostnamectl hostname)"

    # Set up a dummy network for _gateway and _outbound labels
    ip link add foo type dummy
    ip link set up dev foo
    ip addr add 10.0.0.2/24 dev foo
    for i in {128..150}; do
        ip addr add "10.0.0.$i/24" dev foo
    done
    ip route add 10.0.0.1 dev foo
    ip route add default via 10.0.0.1 dev foo

    # Note: `getent hosts` probes gethostbyname2(), whereas `getent ahosts` probes gethostbyname3()
    #       and gethostbyname4() (through getaddrinfo() -> gaih_inet() -> get_nss_addresses())
    getent hosts -s myhostname
    getent ahosts -s myhostname

    # With IPv6 disabled
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    # Everything under .localhost and .localhost.localdomain should resolve to localhost
    for host in {foo.,foo.bar.baz.,.,}localhost{,.} {foo.,foo.bar.baz.,.,}localhost.localdomain{,.}; do
        run_and_grep "^127\.0\.0\.1\s+localhost$" getent hosts -s myhostname "$host"
        run_and_grep "^127\.0\.0\.1\s+STREAM\s+localhost" getent ahosts -s myhostname "$host"
        run_and_grep "^127\.0\.0\.1\s+STREAM\s+localhost" getent ahostsv4 -s myhostname "$host"
        (! getent ahostsv6 -s myhostname localhost)
    done
    for i in 2 {128..150}; do
        run_and_grep "^10\.0\.0\.$i\s+$HOSTNAME$" getent hosts -s myhostname "$HOSTNAME"
        run_and_grep "^10\.0\.0\.$i\s+" getent ahosts -s myhostname "$HOSTNAME"
        run_and_grep "^10\.0\.0\.$i\s+" getent ahostsv4 -s myhostname "$HOSTNAME"
        run_and_grep "^10\.0\.0\.$i\s+$HOSTNAME$" getent hosts -s myhostname "10.0.0.$i"
        run_and_grep "^10\.0\.0\.$i\s+STREAM\s+10\.0\.0\.$i$" getent ahosts -s myhostname "10.0.0.$i"
        run_and_grep "^10\.0\.0\.$i\s+STREAM\s+10\.0\.0\.$i$" getent ahostsv4 -s myhostname "10.0.0.$i"
    done
    for database in hosts ahosts ahostsv4 ahostsv6; do
        (! getent "$database" -s myhostname ::1)
    done
    (! getent ahostsv6 -s myhostname "$HOSTNAME")
    run_and_grep -n "^fe80:[^ ]+\s+STREAM$" getent ahosts -s myhostname "$HOSTNAME"

    # With IPv6 enabled
    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    # Everything under .localhost and .localhost.localdomain should resolve to localhost
    for host in {foo.,foo.bar.baz.,.,}localhost{,.} {foo.,foo.bar.baz.,.,}localhost.localdomain{,.}; do
        run_and_grep "^::1\s+localhost$" getent hosts -s myhostname "$host"
        run_and_grep "^::1\s+STREAM" getent ahosts -s myhostname "$host"
        run_and_grep "^127\.0\.0\.1\s+STREAM" getent ahosts -s myhostname "$host"
        run_and_grep "^127\.0\.0\.1\s+STREAM" getent ahostsv4 -s myhostname "$host"
        run_and_grep -n "^::1\s+STREAM" getent ahostsv4 -s myhostname "$host"
        run_and_grep "^::1\s+STREAM" getent ahostsv6 -s myhostname "$host"
        run_and_grep -n "^127\.0\.0\.1\s+STREAM" getent ahostsv6 -s myhostname "$host"
    done
    for i in 2 {128..150}; do
        run_and_grep "^10\.0\.0\.$i\s+" getent ahosts -s myhostname "$HOSTNAME"
        run_and_grep "^10\.0\.0\.$i\s+" getent ahostsv4 -s myhostname "$HOSTNAME"
        run_and_grep "^10\.0\.0\.$i\s+STREAM\s+10\.0\.0\.$i$" getent ahosts -s myhostname "10.0.0.$i"
        run_and_grep "^10\.0\.0\.$i\s+STREAM\s+10\.0\.0\.$i$" getent ahostsv4 -s myhostname "10.0.0.$i"
    done
    run_and_grep "^fe80:[^ ]+\s+$HOSTNAME$" getent hosts -s myhostname "$HOSTNAME"
    run_and_grep "^fe80:[^ ]+\s+STREAM" getent ahosts -s myhostname "$HOSTNAME"
    run_and_grep "^127\.0\.0\.1\s+localhost$" getent hosts -s myhostname 127.0.0.1
    run_and_grep "^127\.0\.0\.1\s+STREAM\s+127\.0\.0\.1$" getent ahosts -s myhostname 127.0.0.1
    run_and_grep "^::ffff:127\.0\.0\.1\s+STREAM\s+127\.0\.0\.1$" getent ahostsv6 -s myhostname 127.0.0.1
    run_and_grep "^127\.0\.0\.2\s+$HOSTNAME$" getent hosts -s myhostname 127.0.0.2
    run_and_grep "^::1\s+localhost $HOSTNAME$" getent hosts -s myhostname ::1
    run_and_grep "^::1\s+STREAM\s+::1$" getent ahosts -s myhostname ::1
    (! getent ahostsv4 -s myhostname ::1)

    # _gateway
    for host in _gateway{,.} 10.0.0.1; do
        run_and_grep "^10\.0\.0\.1\s+_gateway$" getent hosts -s myhostname "$host"
        run_and_grep "^10\.0\.0\.1\s+STREAM" getent ahosts -s myhostname "$host"
    done

    # _outbound
    for host in _outbound{,.} 10.0.0.2; do
        run_and_grep "^10\.0\.0\.2\s+" getent hosts -s myhostname "$host"
        run_and_grep "^10\.0\.0\.2\s+STREAM" getent ahosts -s myhostname "$host"
    done

    # Non-existent records
    for database in hosts ahosts ahostsv4 ahostsv6; do
        (! getent "$database" -s myhostname this.should.not.exist)
    done
    (! getent hosts -s myhostname 10.254.254.1)
    (! getent hosts -s myhostname fd00:dead:beef:cafe::1)
}

test_varlink() {
    A=$(mktemp -u)
    B=$(mktemp -u)
    varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}' --json=short > "$A"
    hostnamectl --json=short > "$B"
    cmp $A $B
}

run_testcases

touch /testok
