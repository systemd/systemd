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
    local i svc

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
    local i svc

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
    local error_file out_file parameters service_type tmp_file

    out_file="$(mktemp)"
    error_file="$(mktemp)"
    tmp_file="$(mktemp)"
    service_type="_testService$service_id._udp"
    parameters="{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": 16785432 }"

    # shellcheck disable=SC2064
    # Note: unregister the trap once it's fired, otherwise it'll get propagated to functions that call this
    #       one, *sigh*
    # The stop comes first, so the unit is gone before its output files are
    # removed, and is best-effort: a unit which already exited on its own must
    # not make the removal be skipped.
    trap "trap - RETURN; systemctl stop $unit_name 2>/dev/null || :; rm -f $out_file $error_file $tmp_file" RETURN

    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$parameters"

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

testcase_mdns_goodbye_on_stop() {
    : "Stopping resolved must withdraw its published services promptly via goodbye"
    resolvectl flush-caches

    local out_file error_file unit_name service_type
    out_file="$(mktemp)"
    error_file="$(mktemp)"
    unit_name="varlinkctl-goodbye-$SRANDOM.service"
    service_type="_testService6._udp"

    # An EXIT trap, not RETURN: set -e aborts skip RETURN traps, and this subshell's EXIT trap
    # fires however the testcase ends — the infinity browse unit must never outlive it. Armed
    # before anything can fail, so an early abort cleans up the files too.
    # shellcheck disable=SC2064
    trap "systemctl stop $unit_name 2>/dev/null || :; rm -f $out_file $error_file" EXIT

    # Note: --timeout=infinity, since the subscription sits idle between discovery
    # and the goodbye-driven removal, and varlinkctl's default 45s idle timeout
    # could sever it in between on a slow runner.
    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": 16785432 }"

    # Wait until the second container's services have been discovered.
    local ok=0
    for _ in {0..14}; do
        if grep "on $CONTAINER_2" "$out_file" >/dev/null; then ok=1; break; fi
        sleep 2
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Never discovered $CONTAINER_2 services"
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    # Checkpoint the output so we only count 'removed' events produced AFTER the
    # stop -- a match is then provably caused by the goodbye, not by earlier churn.
    local off
    off="$(wc -c <"$out_file")"

    # Gracefully stop resolved in the second container. On a clean stop resolved
    # multicasts mDNS goodbye packets (TTL=0) for its published services, so the
    # browser must observe a 'removed' event for them well before the 120s record
    # TTL would otherwise expire them.
    # The stop runs in the container's own shell, with registration attempts hammering the bus
    # beside it: a RegisterService() arriving in the goodbye grace second must be refused with
    # the dedicated ShuttingDown error -- a service registered then would be gone with the
    # process while its client believes it published. Attempts landing before the stop signal
    # merely register a canary the goodbyes then withdraw; attempts after the exit fail with the
    # bus's own name-gone wording, which is why the refusal's own message is what is looked for:
    # busctl prints "Call failed: <message>" and never the error name (that goes to sd_notify's
    # BUSERROR=, which a transient unit has no socket for), so the message is what is observable.
    # --auto-start=no is what makes the race raceable at all: the unit carries
    # BusName=org.freedesktop.resolve1, so an ordinary call enqueues an activation job that
    # cancels the stop this is timing against ("Job for systemd-resolved.service canceled").
    # The script's variables are the container shell's, hence the single quotes.
    # shellcheck disable=SC2016
    systemd-run -M "$CONTAINER_2" --wait --pipe -- bash -ec '
        systemctl stop systemd-resolved.service &
        stop_pid=$!
        seen=0
        for i in $(seq 1 500); do
            kill -0 "$stop_pid" 2>/dev/null || break
            out="$(busctl --auto-start=no call org.freedesktop.resolve1 /org/freedesktop/resolve1 \
                       org.freedesktop.resolve1.Manager RegisterService "sssqqqaa{say}" \
                       "shutdown-canary-$i" "Shutdown Canary $i" _shutdownbye._udp 4711 0 0 0 2>&1)" && continue
            case "$out" in
                *"Refusing to register a DNS-SD service while shutting down"*) seen=1; break ;;
            esac
            sleep 0.01
        done
        wait "$stop_pid"
        if [ "$seen" -ne 1 ]; then
            echo "No RegisterService() call was refused while systemd-resolved was shutting down" >&2
            exit 1
        fi'

    # Count distinct withdrawn instances rather than stopping at the first one: the goodbye for the
    # container's 200 published services spans several packets, and a truncated emission would still
    # withdraw a random subset of them (the zone is walked in hashmap order). Every instance of the
    # browsed type must go.
    local removed_names removed=0
    for _ in {0..29}; do  # ~60s: generous for slow (sanitizer) runners, still far below the 120s record TTL
        removed_names="$(tail -c "+$((off + 1))" "$out_file" \
                         | { grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' || :; } \
                         | { grep "on $CONTAINER_2" || :; } \
                         | sed 's/.*"name":"//;s/"$//' | sort -u)"
        removed="$(printf '%s\n' "$removed_names" | { grep -c . || :; })"
        if [[ "$removed" -ge "$SERVICE_COUNT" ]]; then
            break
        fi
        sleep 2
    done

    if [[ "$removed" -lt "$SERVICE_COUNT" ]]; then
        echo >&2 "Only $removed of $SERVICE_COUNT $CONTAINER_2 services were 'removed' after stopping its resolved (goodbye missing or truncated?):"
        printf '%s\n' "$removed_names" >&2
        cat "$out_file" "$error_file" >&2
        # Best-effort restore before failing.
        systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl start systemd-resolved.service || :
        return 1
    fi

    # Restore the second container's resolved (and its per-link mDNS/LLMNR
    # overrides, which a resolved restart drops) for the remaining testcases.
    # The freshly started resolved may not have re-enumerated its links yet, in
    # which case resolvectl fails on the not-yet-known 'host0' — retry briefly
    # rather than tripping set -e on the transient.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl start systemd-resolved.service
    ok=0
    for _ in {0..9}; do
        if systemd-run -M "$CONTAINER_2" --wait --pipe -- \
               bash -xec "resolvectl mdns host0 yes; resolvectl llmnr host0 yes"; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Could not re-enable mDNS/LLMNR on $CONTAINER_2's host0 after restarting its resolved"
        return 1
    fi

    echo testcase_end
}

testcase_mdns_runtime_withdrawal() {
    : "Unregistering a service or dropping its file on reload must withdraw exactly that service"
    resolvectl flush-caches

    local out_file error_file unit_name service_type off
    out_file="$(mktemp)"
    error_file="$(mktemp)"
    unit_name="varlinkctl-withdraw-$SRANDOM.service"
    service_type="_withdrawBye._udp"

    # An EXIT trap, not RETURN: set -e aborts skip RETURN traps, and this subshell's EXIT trap
    # fires however the testcase ends — the infinity browse unit must never outlive it. Armed
    # before anything can fail, so an early abort cleans up the files too.
    # shellcheck disable=SC2064
    trap "systemctl stop $unit_name 2>/dev/null || :; rm -f $out_file $error_file" EXIT

    # Two canary services in the second container. Their ids double as their bus object paths,
    # so they must not contain characters the bus path encoding would escape.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- tee /etc/systemd/dnssd/unregbye.dnssd <<EOF
[Service]
Name=Unregister Canary
Type=$service_type
Port=8010
TxtText=DC=Device PN=123456 SN=1234567890
EOF
    systemd-run -M "$CONTAINER_2" --wait --pipe -- tee /etc/systemd/dnssd/reloadbye.dnssd <<EOF
[Service]
Name=Reload Canary
Type=$service_type
Port=8010
TxtText=DC=Device PN=123456 SN=1234567890
EOF
    # Reload rather than restart: it re-runs dnssd_load() to pick up the new files while
    # leaving the runtime per-link mDNS switches from setup intact.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl reload systemd-resolved.service

    # --timeout=infinity: the subscription idles between the events asserted below, longer than
    # varlinkctl's default 45s method-call timeout.
    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": 16785432 }"

    # Wait until both canaries are discovered.
    local ok=0
    for _ in {0..14}; do
        if grep "Unregister Canary" >/dev/null "$out_file" &&
           grep "Reload Canary" >/dev/null "$out_file"; then
            ok=1
            break
        fi
        sleep 2
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Never discovered both canary instances"
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    # Checkpoint the output: only events produced after the unregister count.
    off="$(wc -c <"$out_file")"

    # Unregister the first canary at runtime. Remove its file first, so a later reload cannot
    # resurrect the unregistered instance.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- rm /etc/systemd/dnssd/unregbye.dnssd
    systemd-run -M "$CONTAINER_2" --wait --pipe -- \
        busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager \
        UnregisterService o /org/freedesktop/resolve1/dnssd/unregbye

    # Its goodbye must remove it well before the 120s record TTL...
    local removed=0
    for _ in {0..14}; do
        if tail -c "+$((off + 1))" "$out_file" | { grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' || :; } | grep "Unregister Canary" >/dev/null; then
            removed=1
            break
        fi
        sleep 1
    done
    if [[ "$removed" -ne 1 ]]; then
        echo >&2 "The unregistered canary was not removed by its goodbye"
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    # ...and must withdraw only that service: the sibling canary stays published, so a 'removed'
    # for it here means the unregister withdrew more than the unregistered service.
    sleep 3
    if tail -c "+$((off + 1))" "$out_file" | { grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' || :; } | grep "Reload Canary" >/dev/null; then
        echo >&2 "Unregistering one service withdrew its still-published sibling:"
        tail -c "+$((off + 1))" "$out_file" >&2
        return 1
    fi

    # The type-enumeration PTR (RFC 6763 section 9) is shared by every instance of the type, so the
    # withdrawal filter has to keep it while a sibling still publishes it -- withdrawing it with the
    # first instance would make the whole type vanish from a type enumeration while it is still
    # being served. Nothing else in this file would notice.
    ok=0
    for _ in {0..14}; do
        if resolvectl query -p mdns -t PTR _services._dns-sd._udp.local 2>/dev/null |
               grep -F "$service_type.local" >/dev/null; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "The type-enumeration PTR went away while a sibling of the type is still published"
        resolvectl query -p mdns -t PTR _services._dns-sd._udp.local >&2 || :
        return 1
    fi

    # Checkpoint again, then drop the second canary's file and reload: the reload must withdraw
    # the vanished service with a goodbye, again well before its record TTL.
    off="$(wc -c <"$out_file")"
    systemd-run -M "$CONTAINER_2" --wait --pipe -- rm /etc/systemd/dnssd/reloadbye.dnssd
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl reload systemd-resolved.service

    removed=0
    for _ in {0..14}; do
        if tail -c "+$((off + 1))" "$out_file" | { grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' || :; } | grep "Reload Canary" >/dev/null; then
            removed=1
            break
        fi
        sleep 1
    done
    if [[ "$removed" -ne 1 ]]; then
        echo >&2 "The canary whose file was removed was not withdrawn on reload"
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    echo testcase_end
}

# Helper function to run browse services with a custom ifindex
run_and_check_services_with_ifindex() {
    local service_id="${1:?}"
    local check_func="${2:?}"
    local ifindex="${3:?}"
    local unit_name="varlinkctl-$service_id-$SRANDOM.service"
    local error_file out_file parameters service_type tmp_file

    out_file="$(mktemp)"
    error_file="$(mktemp)"
    tmp_file="$(mktemp)"
    service_type="_testService$service_id._udp"
    parameters="{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": $ifindex, \"flags\": 16785432 }"

    # shellcheck disable=SC2064
    # Note: same as above about unregistering the trap once it's fired
    trap "trap - RETURN; systemctl stop $unit_name 2>/dev/null || :; rm -f $out_file $error_file $tmp_file" RETURN

    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$parameters"

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

testcase_browse_ifindex_zero_no_flap() {
    : "ifindex=0 browse must not emit spurious 'removed' events while publishers stay up"
    resolvectl flush-caches

    local out_file unit_name service_type added removed
    local dummy="ravc-noflap"

    out_file="$(mktemp)"
    unit_name="varlinkctl-noflap-$SRANDOM.service"
    service_type="_testService5._udp"

    # The flap only manifests when the browser reconciles >=2 same-family mDNS
    # scopes: the pre-fix code diffed the browser's global service list against
    # each scope's partial answer, spuriously removing services absent from that
    # one scope. The host normally has only the container bridge as an mDNS
    # interface, so add a service-less dummy link with mDNS enabled to guarantee a
    # second (empty) scope that the ifindex=0 reconciliation must combine. This
    # must succeed -- without the second scope the testcase asserts nothing.
    # A previously interrupted run may have leaked the fixed-name link: RETURN traps
    # do not fire when set -e aborts a function mid-flight, so clear it first to keep
    # re-runs self-healing instead of tripping over EEXIST here.
    ip link del "$dummy" 2>/dev/null || :
    ip link add "$dummy" type dummy
    # Arm the cleanup before anything else can fail, so neither the fixed-name
    # link nor the output file leaks into later testcases: run_testcases runs
    # each testcase in its own subshell, whose EXIT trap fires however the
    # testcase ends. The browse unit may not exist yet, hence the best-effort
    # stop.
    # shellcheck disable=SC2064
    trap "systemctl stop $unit_name 2>/dev/null || :; ip link del $dummy 2>/dev/null || :; rm -f $out_file" EXIT
    ip link set "$dummy" up multicast on
    ip address add 169.254.171.171/16 dev "$dummy"
    resolvectl mdns "$dummy" yes
    [[ "$(resolvectl mdns "$dummy")" =~ :\ yes$ ]]
    sleep 2  # let resolved create the scope before we start browsing

    # Long-running browse across *all* interfaces (ifindex=0). With the
    # combined-answer reconciliation there must be no 'removed' event as long as
    # every publisher stays up. Use --timeout=infinity: the subscription goes idle
    # once everything is discovered, and varlinkctl's default 45s idle timeout
    # would sever it (and the assertion) mid-observation.
    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": 0, \"flags\": 16785432 }"

    # Wait until both containers' services (20 each, 40 total) have been
    # discovered. Count occurrences, not lines: varlinkctl --more emits compact
    # JSON-SEQ and one notify batches many entries onto a single line.
    for _ in {0..14}; do
        added="$( { grep -o '"updateFlag":"added"' "$out_file" || :; } | wc -l)"
        [[ "$added" -ge 40 ]] && break
        sleep 2
    done
    if [[ "${added:-0}" -lt 40 ]]; then
        echo >&2 "Did not discover the expected services on ifindex=0"
        cat "$out_file" >&2
        return 1
    fi

    # Observe a further window during which several continuous-query revisits
    # happen; a correct ifindex=0 browse emits zero 'removed' events while every
    # publisher stays up.
    sleep 12

    removed="$( { grep -o '"updateFlag":"removed"' "$out_file" || :; } | wc -l)"
    if [[ "${removed:-0}" -ne 0 ]]; then
        echo >&2 "Got $removed spurious 'removed' event(s) on ifindex=0 while all publishers were up:"
        grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' "$out_file" >&2 || :
        return 1
    fi

    echo testcase_end
}

testcase_second_unreachable() {
    : "Test each service type while the second container is unreachable"
    systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl down host0
    # Announcements that were already on the wire (or sitting unread in our socket buffer)
    # can straddle a single flush and leak the now-unreachable container back into the
    # cache: resolved's (re)start reliably re-announces every published service, and the
    # preceding testcase restarts the second container's resolved. Flush until the cache
    # stays clean of that container (bounded: the stragglers are only whatever queued up
    # before host0 went down, but on slow sanitizer runners draining it can take a while).
    local clean=0
    for _ in {0..29}; do  # ~60s: the same budget the goodbye-detection loop grants slow runners
        resolvectl flush-caches
        sleep 1
        if ! resolvectl show-cache | grep "$CONTAINER_2" >/dev/null; then
            clean=1
            break
        fi
    done
    if [[ "$clean" -ne 1 ]]; then
        echo >&2 "Cache could not be cleaned of $CONTAINER_2 records after its link went down"
        resolvectl show-cache >&2
        return 1
    fi
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
