#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

. /etc/os-release
if [[ "${ID_LIKE:-}" == alpine ]]; then
    # FIXME: For some reasons (maybe this test requires nss module??), the test fails on alpine/postmarketos.
    exit 77
fi

SERVICE_TYPE_COUNT=10
SERVICE_COUNT=20
CONTAINER_ZONE="test-$RANDOM"
CONTAINER_1="test-mdns-1"
CONTAINER_2="test-mdns-2"

# Prepare containers
create_container() {
    local container="${1:?}"
    local stype sid svc

    # Prepare container's /etc
    #
    # Since we also need the various test suite related dropins from the host's /etc,
    # we'll overlay our customizations on top of that
    mkdir -p "/var/lib/machines/$container/etc/systemd/dnssd"
    # Create 20 test services for each service type (_testServiceX._udp) and number them sequentially,
    # i.e. create services 0-19 for _testService0._udp, services 20-39 for _testService1._udp, and so on
    for stype in $(seq 0 $((SERVICE_TYPE_COUNT - 1))); do
        for sid in $(seq 0 $((SERVICE_COUNT - 1))); do
            svc=$((stype * SERVICE_COUNT + sid))

            cat >"/var/lib/machines/$container/etc/systemd/dnssd/test-service-$container-$svc.dnssd" <<EOF
[Service]
Name=Test Service $svc on %H
Type=_testService$stype._udp
Port=98010
TxtText=DC=Device PN=123456 SN=1234567890
EOF
        done
    done

    # To make things fast, spawn the container with a transient version of what's currently the host's
    # rootfs, with a couple of tweaks to make the container unique enough
    mkdir -p "/run/systemd/system/systemd-nspawn@$container.service.d"
    cat >"/run/systemd/system/systemd-nspawn@$container.service.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=systemd-nspawn --quiet --link-journal=try-guest --keep-unit --machine=%i --boot \
                         --volatile=yes --directory=/ \
                         --inaccessible=/etc/machine-id \
                         --inaccessible=/etc/hostname \
                         --resolv-conf=replace-stub \
                         --network-zone=$CONTAINER_ZONE \
                         --overlay=/etc:/var/lib/machines/$container/etc::/etc \
                         --hostname=$container
EOF
}

check_both() {
    local service_id="${1:?}"
    local result_file="${2:?}"

    # We should get 20 services per container, 40 total
    if [[ "$(wc -l <"$result_file")" -ge 40 ]]; then
        # Check if the services we got are the correct ones
        for i in $(seq 0 $((SERVICE_TYPE_COUNT - 1))); do
            svc=$((service_id * SERVICE_COUNT + i))
            if ! grep "Test Service $svc on $CONTAINER_1" "$result_file" ||
               ! grep "Test Service $svc on $CONTAINER_2" "$result_file"; then
                return 1
            fi
        done

        # We got all records and all of them are what we expect
        return 0
    fi

    return 1
}

check_first() {
    local service_id="${1:?}"
    local result_file="${2:?}"

    # We should get 20 services per container
    if [[ "$(wc -l <"$result_file")" -ge 20 ]]; then
        # Check if the services we got are the correct ones
        for i in $(seq 0 $((SERVICE_TYPE_COUNT - 1))); do
            svc=$((service_id * SERVICE_COUNT + i))
            if ! grep "Test Service $svc on $CONTAINER_1" "$result_file"; then
                return 1
            fi
            # This check assumes the second container is unreachable, so this shouldn't happen
            if grep "Test Service $svc on $CONTAINER_2" "$result_file"; then
                echo >&2 "Found a record from an unreachable container"
                cat "$result_file"
                exit 1
            fi
        done

        # We got all records and all of them are what we expect
        return 0
    fi

    return 1
}

run_and_check_services() {
    local service_id="${1:?}"
    local check_func="${2:?}"
    local unit_name="varlinkctl-$service_id-$SRANDOM.service"
    local i out_file parameters service_type svc tmp_file

    out_file="$(mktemp)"
    error_file="$(mktemp)"
    tmp_file="$(mktemp)"
    service_type="_testService$service_id._udp"
    parameters="{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": 16785432 }"

    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$parameters"

    # shellcheck disable=SC2064
    # Note: unregister the trap once it's fired, otherwise it'll get propagated to functions that call this
    #       one, *sigh*

    trap "trap - RETURN; systemctl stop $unit_name" RETURN

    for _ in {0..14}; do
        # The response format, for reference (it's JSON-SEQ):
        #
        # {
        #   "browser_service_data": [
        #     {
        #       "updateFlag": true,
        #       "family": 10,
        #       "name": "Test Service 13 on test-mdns-1",
        #       "type": "_testService0._udp",
        #       "domain": "local",
        #       "interface": 3
        #     },
        #     ...
        #   ]
        # }
        if [[ -s "$out_file" ]]; then
            # Extract the service name from each valid record...
            # jq --slurp --raw-output \
            #     ".[].browser_service_data[] | select(.updateFlag == true and .type == \"$service_type\" and .family == 10).name" "$out_file" | sort | tee "$tmp_file"
            grep -o '"name":"[^"]*"' "$out_file" | sed 's/"name":"//;s/"//g' | sort | tee "$tmp_file"
            # ...and compare them with what we expect
            if "$check_func" "$service_id" "$tmp_file"; then
                return 0
            fi
        fi

        sleep 2
    done

    cat "$out_file"
    cat "$error_file"
    return 1
}

testcase_all_sequential() {
    : "Test each service type (sequentially)"
    resolvectl flush-caches
    for id in $(seq 0 $((SERVICE_TYPE_COUNT - 1))); do
        run_and_check_services "$id" check_both
    done

    echo testcase_end
}

testcase_all_parallel() {
    : "Test each service type (in parallel)"
    resolvectl flush-caches
    for id in $(seq 0 $((SERVICE_TYPE_COUNT - 1))); do
        run_and_check_services "$id" check_both &
    done
    wait
}

testcase_single_service_multiple_times() {
    : "Test one service type multiple times"
    resolvectl flush-caches
    for _ in {0..4}; do
        run_and_check_services 4 check_both
    done
}

# Helper function to run browse services with a custom ifindex
run_and_check_services_with_ifindex() {
    local service_id="${1:?}"
    local check_func="${2:?}"
    local ifindex="${3:?}"
    local unit_name="varlinkctl-$service_id-$SRANDOM.service"
    local i out_file parameters service_type svc tmp_file

    out_file="$(mktemp)"
    error_file="$(mktemp)"
    tmp_file="$(mktemp)"
    service_type="_testService$service_id._udp"
    parameters="{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": $ifindex, \"flags\": 16785432 }"

    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$parameters"

    # shellcheck disable=SC2064
    # Note: same as above about unregistering the trap once it's fired
    trap "trap - RETURN; systemctl stop $unit_name" RETURN

    for _ in {0..14}; do
        if [[ -s "$out_file" ]]; then
            grep -o '"name":"[^"]*"' "$out_file" | sed 's/"name":"//;s/"//g' | sort | tee "$tmp_file"
            if "$check_func" "$service_id" "$tmp_file"; then
                return 0
            fi
        fi

        sleep 2
    done

    cat "$out_file"
    cat "$error_file"
    return 1
}

testcase_browse_all_interfaces_ifindex_zero() {
    : "Test browsing all interfaces with ifindex=0"
    resolvectl flush-caches
    # Using ifindex=0 should discover services on all mDNS interfaces
    run_and_check_services_with_ifindex 0 check_both 0
}

testcase_second_unreachable() {
    : "Test each service type while the second container is unreachable"
    systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl down host0
    resolvectl flush-caches
    for id in $(seq 0 $((SERVICE_TYPE_COUNT - 1))); do
        run_and_check_services "$id" check_first
    done


    : "Test each service type after bringing the second container back up again"
    systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl up host0
    systemd-run -M "$CONTAINER_2" --wait --pipe -- \
        /usr/lib/systemd/systemd-networkd-wait-online --ipv4 --ipv6 --interface=host0 --operational-state=degraded --timeout=30
    for id in $(seq 0 $((SERVICE_TYPE_COUNT - 1))); do
        run_and_check_services "$id" check_both
    done
}

: "Setup host & containers"
# Note: create the drop-in intentionally under /run/ and copy it manually into the containers
mkdir -p /run/systemd/resolved.conf.d/
cat >/run/systemd/resolved.conf.d/99-mdns-llmnr.conf <<EOF
[Resolve]
MulticastDNS=yes
LLMNR=yes
EOF

systemctl unmask systemd-resolved.service systemd-networkd.{service,socket} systemd-machined.service
systemctl enable --now systemd-resolved.service systemd-networkd.{socket,service} systemd-machined.service
systemctl reload systemd-resolved.service systemd-networkd.service

for container in "$CONTAINER_1" "$CONTAINER_2"; do
    create_container "$container"
    mkdir -p "/var/lib/machines/$container/etc/systemd/resolved.conf.d/"
    cp /run/systemd/resolved.conf.d/99-mdns-llmnr.conf "/var/lib/machines/$container/etc/systemd/resolved.conf.d/"
    touch "/var/lib/machines/$container/etc/hostname"
    systemctl daemon-reload
    machinectl start "$container"
    # Wait for the system bus to start...
    timeout 30s bash -xec "while ! systemd-run -M '$container' --wait --pipe true; do sleep 1; done"
    # ...and from there wait for the machine bootup to finish. We don't really care if the container
    # boots up in a degraded state, hence the `:`
    timeout 30s systemd-run -M "$container" --wait --pipe -- systemctl --wait is-system-running || :
    # Wait until the veth interface is configured and turn on mDNS and LLMNR
    systemd-run -M "$container" --wait --pipe -- \
        /usr/lib/systemd/systemd-networkd-wait-online --ipv4 --ipv6 --interface=host0 --operational-state=degraded --timeout=30
    systemd-run -M "$container" --wait --pipe -- resolvectl mdns host0 yes
    systemd-run -M "$container" --wait --pipe -- resolvectl llmnr host0 yes
    systemd-run -M "$container" --wait --pipe -- networkctl status --no-pager
    systemd-run -M "$container" --wait --pipe -- resolvectl status --no-pager
    [[ "$(systemd-run -M "$container" --wait --pipe -- resolvectl mdns host0)" =~ :\ yes$ ]]
    [[ "$(systemd-run -M "$container" --wait --pipe -- resolvectl llmnr host0)" =~ :\ yes$ ]]
done

BRIDGE_INDEX="$(<"/sys/class/net/vz-$CONTAINER_ZONE/ifindex")"
machinectl list
resolvectl mdns "vz-$CONTAINER_ZONE" on
resolvectl llmnr "vz-$CONTAINER_ZONE" on
networkctl status
resolvectl status

# Run the actual test cases (functions prefixed by testcase_)
run_testcases

touch /testok
