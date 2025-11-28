#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! check_nss_module mymachine; then
    exit 0
fi

at_exit() {
    set +e

    machinectl kill --signal=KILL nss-mymachines-{noip,singleip,manyips}
    mountpoint -q /var/lib/machines && timeout 30 sh -c "until umount /var/lib/machines; do sleep .5; done"
    rm -f /run/systemd/nspawn/*.nspawn
}

trap at_exit EXIT

# Mount temporary directory over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount --bind "$(mktemp --tmpdir=/var/tmp -d)" /var/lib/machines

# Create a bunch of containers that:
# 1) Have no IP addresses assigned
create_dummy_container /var/lib/machines/nss-mymachines-noip
cat >/var/lib/machines/nss-mymachines-noip/sbin/init <<\EOF
#!/usr/bin/env bash
set -ex

ip addr show dev ve-noip
touch /initialized
sleep infinity &
# Run the sleep command asynchronously, so bash is able to process signals
while :; do
    wait || :
done
EOF
# 2) Have one IP address assigned (IPv4 only)
create_dummy_container /var/lib/machines/nss-mymachines-singleip
cat >/var/lib/machines/nss-mymachines-singleip/sbin/init <<\EOF
#!/usr/bin/env bash
set -ex

ip addr add 10.1.0.2/24 dev ve-singleip
ip addr show dev ve-singleip
touch /initialized
sleep infinity &
while :; do
    wait || :
done
EOF
# 3) Have bunch of IP addresses assigned (both IPv4 and IPv6)
create_dummy_container /var/lib/machines/nss-mymachines-manyips
cat >/var/lib/machines/nss-mymachines-manyips/sbin/init <<\EOF
#!/usr/bin/env bash
set -ex

ip addr add 10.2.0.2/24 dev ve-manyips
for i in {100..120}; do
    ip addr add 10.2.0.$i/24 dev ve-manyips
done
ip addr add fd00:dead:beef:cafe::2/64 dev ve-manyips nodad
ip addr show dev ve-manyips
touch /initialized
sleep infinity
while :; do
    wait || :
done
EOF
# Create the respective .nspawn config files
mkdir -p /run/systemd/nspawn
for container in noip singleip manyips; do
    cat >"/run/systemd/nspawn/nss-mymachines-$container.nspawn" <<EOF
[Exec]
Boot=yes

[Network]
VirtualEthernetExtra=ve-$container
EOF
done

# Start the containers and wait until all of them are initialized
machinectl start nss-mymachines-{noip,singleip,manyips}
for container in nss-mymachines-{noip,singleip,manyips}; do
    timeout 30 bash -xec "while [[ ! -e /var/lib/machines/$container/initialized ]]; do sleep .5; done"
done

# We need to configure the dummy interfaces on the "outside" as well for `getent {ahosts4,ahosts6}` to work
# properly. This is caused by getaddrinfo() calling _check_pf() that iterates through all interfaces and
# notes if any of them has an IPv4/IPv6 - this is then used together with AF_INET/AF_INET6 to determine if we
# can ever return a valid answer, and if we configured the container interfaces only in the container, we
# would have no valid IPv4/IPv6 on the "outside" (as we don't set up any other netdev) which would make
# getaddrinfo() return EAI_NONAME without ever asking nss-mymachines.
ip addr add 10.1.0.1/24 dev ve-singleip
ip addr add 10.2.0.1/24 dev ve-manyips
ip addr add fd00:dead:beef:cafe::1/64 dev ve-manyips nodad

getent hosts -s mymachines
getent ahosts -s mymachines

# And finally check if we can resolve the containers via nss-mymachines
for database in hosts ahosts{,v4,v6}; do
    (! getent "$database" -s mymachines nss-mymachines-noip)
done

run_and_grep "^10\.1\.0\.2\s+nss-mymachines-singleip$" getent hosts -s mymachines nss-mymachines-singleip
run_and_grep "^10\.1\.0\.2\s+STREAM" getent ahosts -s mymachines nss-mymachines-singleip
run_and_grep "^10\.1\.0\.2\s+STREAM" getent ahostsv4 -s mymachines nss-mymachines-singleip
run_and_grep "^::ffff:10\.1\.0\.2\s+STREAM" getent ahostsv6 -s mymachines nss-mymachines-singleip

run_and_grep "^fd00:dead:beef:cafe::2\s+nss-mymachines-manyips$" getent hosts -s mymachines nss-mymachines-manyips
run_and_grep "^fd00:dead:beef:cafe::2\s+STREAM" getent ahosts -s mymachines nss-mymachines-manyips
run_and_grep "^10\.2\.0\.2\s+STREAM" getent ahosts -s mymachines nss-mymachines-manyips
for i in {100..120}; do
    run_and_grep "^10\.2\.0\.$i\s+STREAM" getent ahosts -s mymachines nss-mymachines-manyips
    run_and_grep "^10\.2\.0\.$i\s+STREAM" getent ahostsv4 -s mymachines nss-mymachines-manyips
done
run_and_grep "^fd00:dead:beef:cafe::2\s+STREAM" getent ahostsv6 -s mymachines nss-mymachines-manyips
run_and_grep -n "^fd00:" getent ahostsv4 -s mymachines nss-mymachines-manyips
run_and_grep -n "^10\.2:" getent ahostsv6 -s mymachines nss-mymachines-manyips

# Multiple machines at once
run_and_grep "^10\.1\.0\.2\s+nss-mymachines-singleip$" getent hosts -s mymachines nss-mymachines-{singleip,manyips}
run_and_grep "^fd00:dead:beef:cafe::2\s+nss-mymachines-manyips$" getent hosts -s mymachines nss-mymachines-{singleip,manyips}
run_and_grep "^10\.1\.0\.2\s+STREAM" getent ahosts -s mymachines nss-mymachines-{singleip,manyips}
run_and_grep "^10\.2\.0\.2\s+STREAM" getent ahosts -s mymachines nss-mymachines-{singleip,manyips}
run_and_grep "^fd00:dead:beef:cafe::2\s+STREAM" getent ahosts -s mymachines nss-mymachines-{singleip,manyips}

for database in hosts ahosts ahostsv4 ahostsv6; do
    (! getent "$database" -s mymachines foo-bar-baz)
done

# getgrid(), getgrnam(), getpwuid(), and getpwnam() are explicitly handled by nss-mymachines, so probe them
# as well
(! getent group -s mymachines foo 11)
(! getent passwd -s mymachines foo 11)

# Now check the machined's hook for resolved too
run_and_grep "10\.1\.0\.2" resolvectl query nss-mymachines-singleip

run_and_grep "fd00:dead:beef:cafe::2" resolvectl query nss-mymachines-manyips
for i in {100..120}; do
    run_and_grep "10\.2\.0\.$i" resolvectl query nss-mymachines-manyips
done

machinectl stop nss-mymachines-{noip,singleip,manyips}
