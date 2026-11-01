#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

. /etc/os-release
if [[ "${ID_LIKE:-}" == alpine ]]; then
    # FIXME: For some reasons (maybe this test requires nss module??), the test fails on Alpine/Nura.
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

# Launch a long-running BrowseServices subscription on the bridge, writing its notifications to $2
# and its errors to $3. --timeout=infinity, since the subscription idles between the events a
# testcase asserts, longer than varlinkctl's default 45s timeout. The flags are
# MDNS_IPV4|MDNS_IPV6|NO_ZONE|NO_STALE, see src/shared/resolved-def.h.
start_browse() {
    local unit_name="${1:?}" out_file="${2:?}" error_file="${3:?}" service_type="${4:?}"

    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "{ \"domain\": \"$service_type.local\", \"type\": \"\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": 16785432 }"
}

# The 'removed' events that arrived in $1 after byte offset $2, one match per line.
removed_events() {
    local file="${1:?}" off="${2:?}"

    tail -c "+$((off + 1))" "$file" | { grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' || :; }
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

# The publishing container's resolved journal since $1, with any further arguments passed on. Every
# assertion that reads it and every failure that dumps it goes through here, so the unit name, the
# machine and the "an empty journal is not a shell error" guard have one home.
publisher_journal() {
    local since="${1:?}"
    shift

    journalctl -M "$CONTAINER_2" -u systemd-resolved.service --since "$since" "$@" || :
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

# Restart the second container's resolved and re-enable the per-link mDNS/LLMNR switches setup
# turned on, which a restart drops. The fresh resolved may not have re-enumerated its links yet, so
# retry briefly. Runs from the EXIT trap of the testcase that takes that resolver down.
restore_second_container_resolved() {
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl start systemd-resolved.service
    for _ in {0..9}; do
        if systemd-run -M "$CONTAINER_2" --wait --pipe -- \
               bash -xec "resolvectl mdns host0 yes; resolvectl llmnr host0 yes"; then
            return 0
        fi
        sleep 1
    done
    echo >&2 "Could not re-enable mDNS/LLMNR on $CONTAINER_2's host0 after restarting its resolved"
    return 1
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
    # fires however the testcase ends — the infinity browse unit must never outlive it, and the
    # container's resolved, stopped below, must come back with its per-link switches for the
    # testcases after this one. Armed before anything can fail, so an early abort cleans up too.
    # shellcheck disable=SC2064
    trap "systemctl stop $unit_name 2>/dev/null || :; rm -f $out_file $error_file; \
          restore_second_container_resolved || exit 1" EXIT

    start_browse "$unit_name" "$out_file" "$error_file" "$service_type"

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
    # address records as the negative: resolve the container's hostname so its A record sits in the
    # cache, and assert after the stop that the goodbyes did not flush it.
    resolvectl query -p mdns "$CONTAINER_2.local"
    # Match an address record itself: the container's name also appears in the PTR, SRV and TXT
    # records of its 200 services, so a bare name match would survive the very flush this is here to
    # catch. Either family counts.
    resolvectl show-cache | grep -E "$CONTAINER_2\.local IN (A|AAAA)\b" >/dev/null

    # Debug logging for the retransmission assertion below; runtime-only, reset by the restart.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- resolvectl log-level debug
    local since
    since="$(systemd-run -M "$CONTAINER_2" --wait --pipe -- date '+%Y-%m-%d %H:%M:%S')"

    # Checkpoint the output so we only count 'removed' events produced AFTER the
    # stop -- a match is then provably caused by the goodbye, not by earlier churn.
    local off
    off="$(wc -c <"$out_file")"

    # Gracefully stop resolved in the second container: on a clean stop it multicasts goodbyes for
    # its published services, so the browser must see 'removed' for them well before the 120s TTL.
    # The stop runs in the container's own shell with registration attempts hammering the bus beside
    # it, started only once the unit is deactivating: a registration landing before the signal would
    # refresh every SRV and TXT record back into probing, which the goodbye skips, so the removal
    # and host-record checks below would pass on the PTRs alone. A RegisterService() arriving in the
    # grace second must be refused with the ShuttingDown error; attempts after the exit fail with
    # the bus's name-gone wording, so the refusal's message is what is looked for, busctl printing
    # 'Call failed: <message>' and never the error name. --auto-start=no makes the race raceable at
    # all: an ordinary call would enqueue an activation job that cancels the stop. The script's
    # variables are the container shell's, hence the single quotes.
    # shellcheck disable=SC2016
    systemd-run -M "$CONTAINER_2" --wait --pipe -- bash -ec '
        systemctl stop systemd-resolved.service &
        stop_pid=$!
        for i in $(seq 1 500); do
            [ "$(systemctl show -P ActiveState systemd-resolved.service)" = deactivating ] && break
            kill -0 "$stop_pid" 2>/dev/null || break
            sleep 0.01
        done
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

    # Count distinct withdrawn instances rather than stop at the first: the goodbye for 200 services
    # spans several packets, and a truncated emission would still withdraw a random subset.
    local removed_names removed=0
    for _ in {0..29}; do  # ~60s: generous for slow (sanitizer) runners, still far below the 120s record TTL
        removed_names="$(removed_events "$out_file" "$off" \
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
        return 1
    fi

    # The negative pinned before the stop: the container's address record survived the withdrawal,
    # so the still-present host stays resolvable while its resolver is down. Checked as soon as the
    # removals are in, ahead of the journal polls below: nothing refreshes the record's 120s TTL
    # while the container's resolver is down.
    if ! resolvectl show-cache | grep -E "$CONTAINER_2\.local IN (A|AAAA)\b" >/dev/null; then
        echo >&2 "The container's address record did not survive its service withdrawal:"
        resolvectl show-cache >&2 || :
        return 1
    fi

    # RFC 6762 section 8.3 wants goodbyes sent at least twice, one second apart: by the time
    # 'systemctl stop' returned, resolved held its exit and retransmitted. Count the passes that put
    # records on the wire, not the 'sending goodbyes' line, which is logged once per pass before any
    # scope is walked and so appears twice even for an empty second pass. A pass ends at the next
    # runtime withdrawal line: a canary that landed just before the signal loses its client inside
    # the grace second, and that withdrawal logs emission lines of its own. Poll briefly, since the
    # linked journal can lag the stop.
    local goodbyes=0 journal
    for _ in {0..9}; do
        journal="$(publisher_journal "$since")"
        goodbyes="$(awk '
            /Sending mDNS goodbye announcements/ { if (emitted) passes++; emitted = 0; in_pass = 1; next }
            /Withdrawing [0-9]+ DNS-SD record|Retransmitting mDNS withdrawal/ { in_pass = 0; next }
            in_pass && /mDNS announcement packet\(s\) carrying [1-9][0-9]* record\(s\)/ { emitted = 1 }
            END { if (emitted) passes++; print passes + 0 }' <<<"$journal")"
        if [[ "$goodbyes" -ge 2 ]]; then break; fi
        sleep 1
    done
    if [[ "$goodbyes" -lt 2 ]]; then
        echo >&2 "Expected 2 goodbye transmissions carrying records (RFC 6762 §8.3), saw $goodbyes"
        publisher_journal "$since" >&2
        return 1
    fi

    # The goodbye for the container's 200 services does not fit into one packet, and the emission
    # line reports how many a pass took: one would mean the split is gone.
    local packets
    packets="$(awk '
        /Sending mDNS goodbye announcements/ { in_pass = 1; next }
        /Withdrawing [0-9]+ DNS-SD record|Retransmitting mDNS withdrawal/ { in_pass = 0; next }
        in_pass && match($0, /Emitted [0-9]+ mDNS announcement packet\(s\) carrying [1-9]/) {
            split(substr($0, RSTART), f, " "); if (!min || f[2] + 0 < min) min = f[2] + 0 }
        END { print min + 0 }' <<<"$journal")"
    if [[ "$packets" -lt 2 ]]; then
        echo >&2 "A goodbye pass fit into $packets packet(s); the announcement is not being split"
        publisher_journal "$since" >&2
        return 1
    fi

    # And a second apart, not back to back: a wall-clock measurement around the stop would be
    # swamped by its own round trip, so both timestamps come from the journal, one 'sending
    # goodbyes' line per pass.
    local gap_msec
    gap_msec="$( publisher_journal "$since" -o short-unix \
                 | awk '/Sending mDNS goodbye announcements/ { if (!first) first = $1; else last = $1 }
                        END { if (first && last) printf "%d\n", (last - first) * 1000; else print -1 }')"
    if [[ "$gap_msec" -lt 900 ]]; then
        echo >&2 "The two goodbye passes were ${gap_msec}ms apart, not the RFC 6762 §8.3 second"
        publisher_journal "$since" >&2
        return 1
    fi

    echo testcase_end
}

# The host's counterpart: restart its resolved and re-enable mDNS/LLMNR on the bridge, retrying
# briefly for the same reason.
restore_host_resolved() {
    systemctl start systemd-resolved.service
    for _ in {0..9}; do
        if resolvectl mdns "vz-$CONTAINER_ZONE" on && resolvectl llmnr "vz-$CONTAINER_ZONE" on &&
           [[ "$(resolvectl mdns "vz-$CONTAINER_ZONE")" =~ :\ yes$ ]]; then
            return 0
        fi
        sleep 1
    done
    echo >&2 "Could not re-enable mDNS/LLMNR on the bridge after restarting resolved"
    return 1
}

testcase_mdns_no_goodbye_without_services() {
    : "A resolved with no published services must stop without goodbyes or the grace second"

    # The host's resolved browses but publishes no DNS-SD services, so its stop must take the
    # fast path: no goodbye transmission, no one-second exit hold. Debug logging is runtime-only
    # state, dropped again by the restart below.
    resolvectl log-level debug
    local since ok journal
    since="$(date '+%Y-%m-%d %H:%M:%S')"

    # Arm the restore before stopping: this testcase takes the host's resolver down, every testcase
    # after it needs one with the switches setup turned on, and the journal capture below is set -e
    # fatal on purpose.
    trap 'restore_host_resolved || exit 1' EXIT

    systemctl stop systemd-resolved.service

    # Both halves are read off the daemon's own decision lines: the hold is armed only on the path
    # that logs the goodbye transmission, so that line's absence next to the fast path's is the
    # grace second not happening; a wall-clock bound would measure bus round trips and cgroup
    # teardown as much as the daemon. Poll for the fast path's line before the negative: without a
    # positive anchor an empty or not-yet-linked capture satisfies the absence grep like a correct
    # stop does.
    ok=0
    for _ in {0..9}; do
        journalctl --sync || :
        # Take the journal first: piping it straight into grep would let a journalctl failure
        # satisfy these assertions under 'set -o pipefail', with nothing actually checked.
        journal="$(journalctl -u systemd-resolved.service --since "$since")"
        if grep "exiting without a goodbye hold" >/dev/null <<<"$journal"; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Never saw a service-less resolved take its no-goodbye exit path:"
        echo >&2 "$journal"
        return 1
    fi
    if grep "Sending mDNS goodbye announcements" >/dev/null <<<"$journal"; then
        echo >&2 "A service-less resolved sent goodbye announcements on stop:"
        echo >&2 "$journal"
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
    # Announcements already on the wire, or unread in our socket buffer, can straddle a single flush
    # and leak the unreachable container back into the cache: earlier testcases restart the second
    # container's resolved, which re-announces everything. Flush until the cache stays clean of that
    # container, bounded.
    local clean=0 cache_dump
    for _ in {0..29}; do  # ~30s, bounded
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
