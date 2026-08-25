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

# Did any 'removed' event whose name matches $3 arrive in $1 after byte offset $2?
removed_since() {
    local file="${1:?}" off="${2:?}" needle="${3:?}"

    tail -c "+$((off + 1))" "$file" | { grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' || :; } | grep -e "$needle" >/dev/null
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

    # Wait until ALL of the second container's instances of this type have been discovered: a
    # 'removed' is only emitted for an instance the browser knew about, so the assertion below
    # requires every one of the $SERVICE_COUNT instances to have arrived before the stop.
    local ok=0 seen
    for _ in {0..29}; do
        seen="$( { grep -oE '"updateFlag":"added"[^}]*"name":"[^"]*"' "$out_file" || :; } \
                 | { grep "on $CONTAINER_2" || :; } \
                 | sed 's/.*"name":"//;s/"$//' | sort -u | { grep -c . || :; })"
        if [[ "$seen" -ge "$SERVICE_COUNT" ]]; then ok=1; break; fi
        sleep 2
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Only discovered $seen of $SERVICE_COUNT $CONTAINER_2 services"
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    # The shutdown goodbye must withdraw the published DNS-SD records only. Pin the host's own
    # address records as the negative: resolve the container's hostname so its A record sits in
    # the cache, and assert after the stop that the goodbyes did not flush it -- a TTL=0
    # cache-flush goodbye for it would break resolution of the still-present host for the whole
    # restart.
    resolvectl query -p mdns "$CONTAINER_2.local"
    # Match an address record itself: the container's name also appears in the PTR, SRV and TXT
    # records of its 200 published services, so a bare name match would survive the very flush this
    # is here to catch. Either family counts — which one answers depends on the runner, and the
    # exemption under test covers both.
    resolvectl show-cache | grep -E "$CONTAINER_2\.local IN (A|AAAA)\b" >/dev/null

    # Debug logging for the retransmission assertion below; runtime-only, reset by the restart.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- resolvectl log-level debug
    local since
    since="$(systemd-run -M "$CONTAINER_2" --wait --pipe -- date '+%Y-%m-%d %H:%M:%S')"

    # Checkpoint the output so we only count 'removed' events produced AFTER the
    # stop -- a match is then provably caused by the goodbye, not by earlier churn.
    local off
    off="$(wc -c <"$out_file")"

    # Gracefully stop resolved in the second container. On a clean stop resolved
    # multicasts mDNS goodbye packets (TTL=0) for its published services, so the
    # browser must observe a 'removed' event for them well before the 120s record
    # TTL would otherwise expire them.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl stop systemd-resolved.service

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

    # RFC 6762 §8.3 wants unsolicited announcements -- goodbyes included -- sent at least twice,
    # one second apart: by the time 'systemctl stop' returned, resolved held its exit for the
    # grace second and retransmitted. Both transmissions log at debug level; poll briefly since
    # the linked journal can lag the stop.
    local goodbyes=0
    for _ in {0..9}; do
        goodbyes="$( { journalctl -M "$CONTAINER_2" -u systemd-resolved.service --since "$since" || :; } \
                     | { grep -c "Sending mDNS goodbye announcements" || :; })"
        if [[ "$goodbyes" -ge 2 ]]; then break; fi
        sleep 1
    done
    if [[ "$goodbyes" -lt 2 ]]; then
        echo >&2 "Expected 2 goodbye transmissions (RFC 6762 §8.3), saw $goodbyes"
        journalctl -M "$CONTAINER_2" -u systemd-resolved.service --since "$since" >&2 || :
        systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl start systemd-resolved.service || :
        return 1
    fi

    # The negative pinned before the stop: the container's address record survived the service
    # withdrawal, so the still-present host stays resolvable from the cache while its resolver
    # is down.
    resolvectl show-cache | grep -E "$CONTAINER_2\.local IN (A|AAAA)\b" >/dev/null

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

testcase_mdns_bus_client_vanish_withdrawal() {
    : "A bus-registered service must be withdrawn with a goodbye when its client vanishes"

    # The client below registers over the bus from python3 via ctypes, which dlopens libsystemd.
    # Under the sanitizers that library is instrumented and loading it into an uninstrumented
    # interpreter is refused outright ("ASan runtime does not come first in initial library list"),
    # so the client would die before registering anything.
    if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
        echo "Sanitizer build: skipping, the ctypes bus client cannot load an instrumented libsystemd"
        return 0
    fi

    resolvectl flush-caches

    local out_file error_file unit_name service_type off ok removed
    out_file="$(mktemp)"
    error_file="$(mktemp)"
    unit_name="varlinkctl-vanish-$SRANDOM.service"
    service_type="_vanishBye._udp"

    # shellcheck disable=SC2064
    trap "systemctl stop $unit_name 2>/dev/null || :; \
          systemd-run -M $CONTAINER_2 --wait --pipe -- systemctl stop vanish-client.service 2>/dev/null || :; \
          rm -f $out_file $error_file" EXIT

    # A DNS-SD service registered over the bus (RegisterService) rather than from a .dnssd file:
    # resolved tracks the registering connection and must withdraw the service with a goodbye
    # when the client goes away without unregistering. The client holds its bus connection open
    # from a transient unit until it is SIGKILLed below -- busctl cannot stand in for it, it
    # disconnects right after the call returns, before the service would even finish probing.
    systemd-run -M "$CONTAINER_2" --unit=vanish-client.service --service-type=exec -- \
        python3 -c '
import ctypes, time
sd = ctypes.CDLL("libsystemd.so.0")
bus = ctypes.c_void_p()
r = sd.sd_bus_open_system(ctypes.byref(bus))
assert r >= 0, r
r = sd.sd_bus_call_method(
        bus, b"org.freedesktop.resolve1", b"/org/freedesktop/resolve1",
        b"org.freedesktop.resolve1.Manager", b"RegisterService", None, None,
        b"sssqqqaa{say}",
        b"vanishbye", b"Vanish Canary", b"_vanishBye._udp",
        ctypes.c_int(8010), ctypes.c_int(0), ctypes.c_int(0), ctypes.c_uint(0))
assert r >= 0, r
time.sleep(3600)
'

    # --timeout=infinity: the subscription idles between the events asserted below, longer than
    # varlinkctl's default 45s method-call timeout.
    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": 16785432 }"

    ok=0
    for _ in {0..14}; do
        if grep "Vanish Canary" "$out_file" >/dev/null; then
            ok=1
            break
        fi
        sleep 2
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Never discovered the bus-registered canary"
        systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl status vanish-client.service >&2 || :
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    # Checkpoint, then kill the client without any chance to clean up: only the tracked bus
    # connection's demise tells resolved the service's owner is gone.
    off="$(wc -c <"$out_file")"
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl kill --signal=SIGKILL vanish-client.service

    removed=0
    for _ in {0..14}; do
        if removed_since "$out_file" "$off" "Vanish Canary"; then
            removed=1
            break
        fi
        sleep 1
    done
    if [[ "$removed" -ne 1 ]]; then
        echo >&2 "The canary was not withdrawn after its registering client vanished"
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    echo testcase_end
}

testcase_mdns_no_goodbye_without_services() {
    : "A resolved with no published services must stop without goodbyes or the grace second"

    # The host's resolved browses but publishes no DNS-SD services, so its stop must take the
    # fast path: no goodbye transmission, no one-second exit hold. Debug logging is runtime-only
    # state, dropped again by the restart below.
    resolvectl log-level debug
    local since ok journal
    since="$(date '+%Y-%m-%d %H:%M:%S')"

    systemctl stop systemd-resolved.service
    journalctl --sync || :
    # Take the journal first: piping it straight into grep would let a journalctl failure satisfy
    # this negative assertion under 'set -o pipefail', with nothing actually checked.
    journal="$(journalctl -u systemd-resolved.service --since "$since")"
    if grep "Sending mDNS goodbye announcements" >/dev/null <<<"$journal"; then
        echo >&2 "A service-less resolved sent goodbye announcements on stop:"
        echo >&2 "$journal"
        systemctl start systemd-resolved.service || :
        return 1
    fi

    # Restore: the restart drops the runtime per-link mDNS/LLMNR switches from setup, and the
    # freshly started resolved may not have re-enumerated its links yet -- retry briefly.
    systemctl start systemd-resolved.service
    ok=0
    for _ in {0..9}; do
        if resolvectl mdns "vz-$CONTAINER_ZONE" on && resolvectl llmnr "vz-$CONTAINER_ZONE" on; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Could not re-enable mDNS/LLMNR on the bridge after restarting resolved"
        return 1
    fi
    [[ "$(resolvectl mdns "vz-$CONTAINER_ZONE")" =~ :\ yes$ ]]

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

    # Three canary services in the second container. Their ids double as their bus object paths,
    # so they must not contain characters the bus path encoding would escape. The third stays
    # published throughout: it is the control that an unchanged .dnssd file survives a reload
    # without being withdrawn.
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
    systemd-run -M "$CONTAINER_2" --wait --pipe -- tee /etc/systemd/dnssd/keepbye.dnssd <<EOF
[Service]
Name=Keep Canary
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

    # Wait until all three canaries are discovered.
    local ok=0
    for _ in {0..14}; do
        if grep "Unregister Canary" "$out_file" >/dev/null &&
           grep "Reload Canary" "$out_file" >/dev/null &&
           grep "Keep Canary" "$out_file" >/dev/null; then
            ok=1
            break
        fi
        sleep 2
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Never discovered all three canary instances"
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
        if removed_since "$out_file" "$off" "Unregister Canary"; then
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
    # for it here means the unregister withdrew more than the unregistered service. Anchor the
    # negative on a positive fact rather than a bare sleep, so a too-short window cannot make it
    # pass vacuously: once the sibling still resolves freshly after the goodbye's one-second
    # retransmission window has passed, any spurious withdrawal would have reached the browser's
    # output by now.
    sleep 2
    ok=0
    for _ in {0..14}; do
        if resolvectl service "Reload Canary" "$service_type" local >/dev/null; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "The sibling canary no longer resolves after unregistering its sibling"
        cat "$out_file" "$error_file" >&2
        return 1
    fi
    if removed_since "$out_file" "$off" "Reload Canary"; then
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
        if removed_since "$out_file" "$off" "Reload Canary"; then
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

    # The reload must leave the untouched canary alone: a 'removed' for it means the reload
    # reconciliation withdrew a service whose file survived unchanged. Same positive anchoring
    # as above.
    sleep 2
    ok=0
    for _ in {0..14}; do
        if resolvectl service "Keep Canary" "$service_type" local >/dev/null; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "The kept canary no longer resolves after the reload"
        cat "$out_file" "$error_file" >&2
        return 1
    fi
    if removed_since "$out_file" "$off" "Keep Canary"; then
        echo >&2 "A reload withdrew a service whose .dnssd file survived unchanged:"
        tail -c "+$((off + 1))" "$out_file" >&2
        return 1
    fi

    # Reload reconciliation is per-RR, not per-service: change only the port. The PTR and TXT
    # survive unchanged -- the browser must see no 'removed' -- while the SRV is replaced, so
    # the service must come to resolve with the new port.
    off="$(wc -c <"$out_file")"
    systemd-run -M "$CONTAINER_2" --wait --pipe -- sed -i 's/^Port=8010$/Port=8011/' /etc/systemd/dnssd/keepbye.dnssd
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl reload systemd-resolved.service

    ok=0
    for _ in {0..14}; do
        if resolvectl service "Keep Canary" "$service_type" local | grep ":8011" >/dev/null; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "The kept canary did not come to resolve with its changed port"
        cat "$out_file" "$error_file" >&2
        return 1
    fi
    if removed_since "$out_file" "$off" "Keep Canary"; then
        echo >&2 "A port-only change withdrew the whole service on reload:"
        tail -c "+$((off + 1))" "$out_file" >&2
        return 1
    fi

    # Withdraw the kept canary again. Best-effort cleanup.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- rm /etc/systemd/dnssd/keepbye.dnssd || :
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl reload systemd-resolved.service || :

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
    local clean=0 cache_dump
    for _ in {0..29}; do  # ~60s: the same budget the goodbye-detection loop grants slow runners
        resolvectl flush-caches
        sleep 1
        # Capture the dump first: under pipefail a failing resolvectl would make the negated
        # pipeline pass and declare a clean cache on what was really a transient dump error.
        if cache_dump="$(resolvectl show-cache)" && ! grep "$CONTAINER_2" >/dev/null <<<"$cache_dump"; then
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
