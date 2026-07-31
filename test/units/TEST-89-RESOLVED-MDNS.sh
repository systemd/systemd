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

# --- mDNS/DNS-SD conformance scorecard ---------------------------------------
#
# The following testcase runs resolved against a scripted mDNS peer
# (TEST-89-RESOLVED-MDNS.peer.py) and scores its behavior scenario by scenario.
# Each scenario names the RFC 6762/6763 requirement it checks, or the
# interoperability report behind it.
#
# The point of the scorecard is to *track* conformance: scenarios that
# currently fail are listed in the known-failures table below (with a
# reference) and do not fail the test. A known-failing scenario that starts to
# pass fails the test instead, so whatever change fixed it must also remove
# the table entry -- keeping the scorecard an accurate record of what works,
# what does not, and which change fixed what.
#
# Unlike the container-based testcases above, these scenarios talk to
# publishers that we control at the packet level (dedicated veth pairs into a
# network namespace), so they can exercise behavior that well-behaved
# publishers never trigger: same-name announcements from multiple interfaces,
# goodbye-less disappearance, per-interface goodbyes, etc. IPv6 is disabled on
# the test links to keep the expected event stream exact (family 2 only).

REF_NS="mdnsref"
REF_IF1="mdnsref1"
REF_IF2="mdnsref2"
REF_SERVICE="_ref._udp"
REF_PUB_SERVICE="_refpub._udp"
REF_PUB_INSTANCE="RefPub89"
REF_PUB_DNSSD_FILE="/run/systemd/dnssd/refpub89.dnssd"
REF_PEER_PY="$(dirname "$0")/TEST-89-RESOLVED-MDNS.peer.py"
# SD_RESOLVED_MDNS_IPV4|SD_RESOLVED_MDNS_IPV6|SD_RESOLVED_NO_ZONE|SD_RESOLVED_NO_STALE,
# i.e. what the other testcases in this file pass.
REF_BROWSE_FLAGS=16785432
# The same minus SD_RESOLVED_NO_STALE (1 << 24): what a plain external client
# that does not know about resolved-internal staleness handling would pass.
REF_BROWSE_FLAGS_PLAIN=8216

REF_PEER_PIDS=()
REF_BROWSE_UNITS=()
REF_LAST_PEER_PID=""
REF_LISTENER_PID=""
REF_TMPDIR=""
REF_IF1_INDEX=""
REF_IF2_INDEX=""

# Count browse events in a JSON-SEQ output file. The key order within one
# event object is fixed (it mirrors the field order on the wire), so a plain
# extended regex is exact. IPv6 is disabled on the reference links, hence no
# per-family disambiguation is needed.
ref_count_events() {
    local file="${1:?}" flag="${2:?}" instance="${3:?}" ifindex="${4:-}"
    local pattern

    pattern="\"updateFlag\":\"$flag\",\"family\":[0-9]+,\"name\":\"$instance\",\"type\":\"$REF_SERVICE\",\"domain\":\"local\""
    [[ -n "$ifindex" ]] && pattern+=",\"ifindex\":$ifindex}"

    { grep -oE "$pattern" "$file" 2>/dev/null || :; } | wc -l
}

ref_wait_event() {
    local file="${1:?}" flag="${2:?}" instance="${3:?}" ifindex="${4:-}" iterations="${5:?}"
    local i

    for ((i = 0; i < iterations; i++)); do
        [[ "$(ref_count_events "$file" "$flag" "$instance" "$ifindex")" -ge 1 ]] && return 0
        sleep 1
    done

    return 1
}

# Like ref_wait_event, but matches on the instance name only -- for scenarios
# (mixed-case or subtype browses) where the exact type string echoed back in
# the event is not the point being scored.
ref_wait_added_name() {
    local file="${1:?}" instance="${2:?}" iterations="${3:?}"
    local i

    for ((i = 0; i < iterations; i++)); do
        if grep -E "\"updateFlag\":\"added\",\"family\":[0-9]+,\"name\":\"$instance\"" >/dev/null 2>&1 "$file"; then
            return 0
        fi
        sleep 1
    done

    return 1
}

ref_start_browse() {
    local out_file="${1:?}" ifindex="${2:?}" flags="${3:-$REF_BROWSE_FLAGS}" domain="${4:-$REF_SERVICE.local}"
    local unit="varlinkctl-ref-$SRANDOM.service"

    # --timeout=infinity: the subscription must outlive varlinkctl's default
    # 45s idle timeout, see the comments in the other testcases.
    systemd-run --unit="$unit" --service-type=exec -p StandardOutput="file:$out_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "{ \"domain\": \"$domain\", \"type\": \"\", \"ifindex\": $ifindex, \"flags\": $flags }" || return 2

    REF_BROWSE_UNITS+=("$unit")
}

ref_query() {
    # Usage: ref_query <log_file> <qname> [extra peer args...]
    local log_file="${1:?}" qname="${2:?}"
    shift 2

    ip netns exec "$REF_NS" python3 "$REF_PEER_PY" query \
        --iface "${REF_IF1}p" --qname "$qname" "$@" >"$log_file" 2>&1
}

ref_start_peer() {
    local log_file="${1:?}" iface="${2:?}" addr="${3:?}" instance="${4:?}"
    shift 4

    ip netns exec "$REF_NS" python3 "$REF_PEER_PY" publish \
        --iface "$iface" --addr "$addr" --instance "$instance" --service "$REF_SERVICE" \
        --hostname "refpeer-$iface.local" "$@" >"$log_file" 2>&1 &

    REF_LAST_PEER_PID=$!
    REF_PEER_PIDS+=("$REF_LAST_PEER_PID")
}

# Reset all per-scenario state: peers, browse subscriptions, caches.
ref_scenario_cleanup() {
    local pid unit

    for pid in "${REF_PEER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || :
    done
    for pid in "${REF_PEER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || :
    done
    REF_PEER_PIDS=()

    # Scenarios that return early may leave their listener running; reap it
    # here so it cannot keep capturing into the next scenario.
    if [[ -n "$REF_LISTENER_PID" ]]; then
        kill "$REF_LISTENER_PID" 2>/dev/null || :
        wait "$REF_LISTENER_PID" 2>/dev/null || :
        REF_LISTENER_PID=""
    fi

    for unit in "${REF_BROWSE_UNITS[@]}"; do
        systemctl stop "$unit" 2>/dev/null || :
    done
    REF_BROWSE_UNITS=()

    resolvectl flush-caches || :
}

ref_teardown() {
    ref_scenario_cleanup

    ip netns del "$REF_NS" 2>/dev/null || :
    ip link del "$REF_IF1" 2>/dev/null || :
    ip link del "$REF_IF2" 2>/dev/null || :

    if ! systemctl is-active systemd-resolved.service >/dev/null; then
        systemctl start systemd-resolved.service 2>/dev/null || :
        ref_restore_after_resolved_restart || :
    fi
    rm -f "$REF_PUB_DNSSD_FILE"
    systemctl reload systemd-resolved.service 2>/dev/null || :

    rm -rf "$REF_TMPDIR"
}

# A freshly (re)started resolved may not have re-enumerated the links yet, so
# retry re-enabling mDNS/LLMNR on the container bridge for a bounded while.
ref_restore_after_resolved_restart() {
    local i

    for i in {0..19}; do
        if resolvectl mdns "vz-$CONTAINER_ZONE" on 2>/dev/null &&
           resolvectl llmnr "vz-$CONTAINER_ZONE" on 2>/dev/null; then
            return 0
        fi
        sleep 1
    done

    return 1
}

# Scenario exit codes: 0 = pass, 1 = tracked conformance failure,
# anything else = broken test harness (always fails the testcase).

ref_scenario_announce() {
    : "Baseline: one publisher, exactly one added event, none removed while it stays up"
    local out="$REF_TMPDIR/announce.browse" peer_log="$REF_TMPDIR/announce.peer"

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefAnnounce || return 2

    ref_wait_event "$out" added RefAnnounce "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 1; }

    # Quiet window: several continuous-query revisits happen, and the peer
    # keeps answering them, so nothing may be added again or removed.
    sleep 5
    [[ "$(ref_count_events "$out" added RefAnnounce)" -eq 1 ]] || { cat "$out" "$peer_log" >&2; return 1; }
    [[ "$(ref_count_events "$out" removed RefAnnounce)" -eq 0 ]] || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_two_interfaces_same_name() {
    : "The same instance name announced on two links yields an added event per link (libcups#81)"
    # https://github.com/OpenPrinting/libcups/issues/81#issuecomment-5122506798
    local out="$REF_TMPDIR/twoif.browse" peer1_log="$REF_TMPDIR/twoif.peer1" peer2_log="$REF_TMPDIR/twoif.peer2"

    ref_start_browse "$out" 0 || return 2
    ref_start_peer "$peer1_log" "${REF_IF1}p" 169.254.89.2 RefTwoIf || return 2
    # Positive control, the tracked assertion is the second link below.
    ref_wait_event "$out" added RefTwoIf "$REF_IF1_INDEX" 30 || { cat "$out" "$peer1_log" >&2; return 2; }

    ref_start_peer "$peer2_log" "${REF_IF2}p" 169.254.90.2 RefTwoIf || return 2
    if ! ref_wait_event "$out" added RefTwoIf "$REF_IF2_INDEX" 10; then
        # Distinguish the tracked conformance failure from a peer that died.
        kill -0 "$REF_LAST_PEER_PID" 2>/dev/null || { cat "$out" "$peer2_log" >&2; return 2; }
        cat "$out" "$peer2_log" >&2
        return 1
    fi
}

ref_scenario_goodbye() {
    : "A goodbye (TTL=0) announcement promptly yields a removed event (RFC 6762 section 10.1)"
    local out="$REF_TMPDIR/goodbye.browse" peer_log="$REF_TMPDIR/goodbye.peer"

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefGoodbye --goodbye-on-exit || return 2
    ref_wait_event "$out" added RefGoodbye "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 2; }

    kill "$REF_LAST_PEER_PID" || return 2
    # RFC 6762 section 10.1: queriers delete goodbyed records after one second.
    ref_wait_event "$out" removed RefGoodbye "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_goodbye_one_interface() {
    : "A goodbye on one link removes only that link's instance, the other lives on (libcups#81)"
    local out="$REF_TMPDIR/halfbye.browse" peer1_log="$REF_TMPDIR/halfbye.peer1" peer2_log="$REF_TMPDIR/halfbye.peer2"
    local peer2_pid

    ref_start_browse "$out" 0 || return 2
    ref_start_peer "$peer1_log" "${REF_IF1}p" 169.254.89.2 RefHalfBye || return 2
    ref_wait_event "$out" added RefHalfBye "$REF_IF1_INDEX" 30 || { cat "$out" "$peer1_log" >&2; return 2; }

    ref_start_peer "$peer2_log" "${REF_IF2}p" 169.254.90.2 RefHalfBye --goodbye-on-exit || return 2
    peer2_pid="$REF_LAST_PEER_PID"
    # The added event for the second link is scenario two_interfaces_same_name's
    # business; give the announcements a moment, then say goodbye on link 2 only.
    sleep 3
    kill "$peer2_pid" || return 2

    ref_wait_event "$out" removed RefHalfBye "$REF_IF2_INDEX" 10 || { cat "$out" "$peer1_log" "$peer2_log" >&2; return 1; }
    # The publisher on link 1 is still alive and answering, so its instance
    # must not have been removed.
    [[ "$(ref_count_events "$out" removed RefHalfBye "$REF_IF1_INDEX")" -eq 0 ]] || { cat "$out" >&2; return 1; }
}

ref_scenario_expiry_no_goodbye() {
    : "A publisher vanishing without goodbye is removed when its records expire (RFC 6762 section 10)"
    local out="$REF_TMPDIR/expiry.browse" peer_log="$REF_TMPDIR/expiry.peer"

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefExpiry --ttl 20 || return 2
    ref_wait_event "$out" added RefExpiry "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 2; }

    # Vanish abruptly: no goodbye, and nobody answers re-confirmation queries.
    kill -KILL "$REF_LAST_PEER_PID" || return 2

    # The records were announced with a 20s TTL, so a conforming querier
    # removes the service within ~20s of the last answer; poll generously.
    ref_wait_event "$out" removed RefExpiry "$REF_IF1_INDEX" 60 || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_expiry_no_goodbye_plain_flags() {
    : "Silent expiry is reported to clients passing plain flags, too (RFC 6762 section 10)"
    # Same as expiry_no_goodbye, but browsing with the flags an external client
    # would pass, i.e. without SD_RESOLVED_NO_STALE. Record expiry must not be
    # an implementation detail that only resolved's own tooling gets to see.
    local out="$REF_TMPDIR/expiryplain.browse" peer_log="$REF_TMPDIR/expiryplain.peer"

    ref_start_browse "$out" "$REF_IF1_INDEX" "$REF_BROWSE_FLAGS_PLAIN" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefExpiryPlain --ttl 20 || return 2
    ref_wait_event "$out" added RefExpiryPlain "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 2; }

    kill -KILL "$REF_LAST_PEER_PID" || return 2

    ref_wait_event "$out" removed RefExpiryPlain "$REF_IF1_INDEX" 60 || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_case_insensitive_match() {
    : "Names must match case-insensitively (RFC 6762 section 16)"
    local out="$REF_TMPDIR/case.browse" peer_log="$REF_TMPDIR/case.peer"

    # Subscribe with the all-lowercase type; the peer announces mixed case.
    # The later --service wins over the one ref_start_peer passes.
    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefCase --service _Ref._UDP || return 2

    ref_wait_added_name "$out" RefCase 30 || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_querier_known_answers() {
    : "Continuous queries carry cached records as known answers (RFC 6762 section 7.1)"
    local out="$REF_TMPDIR/ka.browse" peer_log="$REF_TMPDIR/ka.peer" listen_log="$REF_TMPDIR/ka.listen"

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefKA || return 2
    ref_wait_event "$out" added RefKA "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 2; }

    # Capture the browser's next continuous re-queries; with the record cached,
    # they must carry it as a known answer in their answer section. The
    # re-query intervals double, so the window must be longer than the largest
    # gap that can still start inside it after a slow discovery (~35s covers a
    # re-query at 64s after browse start even in the worst case). The worst
    # case leaves a single re-query in the window, so rather than fail the
    # whole testcase on one lost datagram, retry the capture once.
    local got_query=0
    for _ in 1 2; do
        ref_start_listener "$listen_log" 35 || return 2
        wait "$REF_LISTENER_PID" || return 2
        if grep "Q name=$REF_SERVICE.local qtype=12" >/dev/null "$listen_log"; then
            got_query=1
            break
        fi
    done

    # Positive control: at least one re-query must fall into the window.
    [[ "$got_query" -eq 1 ]] || { cat "$listen_log" >&2; return 2; }
    grep -E "R qr=0 dst=[^ ]+ sec=an .* ptr=RefKA\.$REF_SERVICE\.local" >/dev/null "$listen_log" || { cat "$listen_log" >&2; return 1; }
}

ref_scenario_duplicate_question_suppression() {
    : "A second browser for the same question adds no queries on the wire (RFC 6762 section 7.3)"
    # Reference behavior (in the spirit of RFC 6762 section 7.3): one question
    # on the wire, no matter how many local subscribers. Today every
    # subscriber runs its own query engine, so traffic scales with the
    # subscriber count.
    local out_a="$REF_TMPDIR/dup.browse-a" out_b="$REF_TMPDIR/dup.browse-b"
    local peer_log="$REF_TMPDIR/dup.peer" listen_log="$REF_TMPDIR/dup.listen"
    local queries

    ref_start_browse "$out_a" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefDup || return 2
    ref_wait_event "$out_a" added RefDup "$REF_IF1_INDEX" 30 || { cat "$out_a" "$peer_log" >&2; return 2; }

    # Let the first browser's re-query schedule back off (the intervals
    # double), so at most one of its queries can fall into the window below.
    sleep 10

    ref_start_listener "$listen_log" 15 || return 2
    ref_start_browse "$out_b" "$REF_IF1_INDEX" || return 2

    # Positive control: the second subscriber must get the service, too.
    ref_wait_event "$out_b" added RefDup "$REF_IF1_INDEX" 10 || { cat "$out_b" >&2; return 2; }

    # Liveness canary: multicast loops back to local group members, so this
    # marker query must show up in the capture. It proves the listener was
    # capturing throughout the window -- a scenario whose PASS condition is
    # the *absence* of queries must not pass on a dead or deaf listener.
    ref_query "$REF_TMPDIR/dup.marker" "refmark._udp.local" --duration 1 || return 2
    wait "$REF_LISTENER_PID" || return 2
    grep "Q name=refmark._udp.local" >/dev/null "$listen_log" || { cat "$listen_log" >&2; return 2; }

    # More than one query in the window means the second subscriber spawned
    # its own query engine (a fresh engine starts at ~1s intervals).
    queries="$({ grep -c "Q name=$REF_SERVICE.local qtype=12" "$listen_log" || :; })"
    [[ "$queries" -le 1 ]] || { cat "$listen_log" >&2; return 1; }
}

ref_scenario_browse_subtype() {
    : "Browsing a service subtype yields its instances (RFC 6763 section 7.1)"
    local out="$REF_TMPDIR/subtype.browse" peer_log="$REF_TMPDIR/subtype.peer"

    ref_start_browse "$out" "$REF_IF1_INDEX" "" "_vendor._sub.$REF_SERVICE.local" || return 2
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefSub --subtype _vendor || return 2

    ref_wait_added_name "$out" RefSub 30 || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_responder_service_enumeration() {
    : "Service type enumeration lists registered types (RFC 6763 section 9)"
    local q_log="$REF_TMPDIR/enum.query"

    # RefPub89 is still registered and announced (see publisher_probe_announce).
    # One retry, like any real querier would: a single datagram each way is not
    # a fair single point of failure on a loaded runner.
    for _ in 1 2; do
        ref_query "$q_log" "_services._dns-sd._udp.local" --duration 5 || return 2
        # flush=0: the enumeration PTR is a shared record -- every responder
        # on the link contributes its own types, so the cache-flush bit must
        # be clear on it (RFC 6762 section 10.2, RFC 6763 section 4.1).
        grep -E "R qr=1 dst=[^ ]+ sec=an name=_services._dns-sd._udp.local type=12 ttl=[1-9][0-9]* flush=0 ptr=$REF_PUB_SERVICE\.local" \
            >/dev/null "$q_log" && return 0
    done

    cat "$q_log" >&2
    return 1
}

ref_scenario_responder_legacy_unicast() {
    : "Legacy queries from an ephemeral port get unicast replies (RFC 6762 section 6.7)"
    local q_log="$REF_TMPDIR/legacy.query"

    for _ in 1 2; do
        ref_query "$q_log" "$REF_PUB_SERVICE.local" --source-port 0 --duration 5 || return 2
        # The reply must be unicast to the querier's ephemeral port (a (wrong)
        # multicast-only reply would go to 224.0.0.251:5353 and never reach
        # this socket, showing up as an empty log), must echo the query's
        # transaction ID (section 6.7) or a real legacy client could never
        # match it to its query -- 35081 is the peer's QUERY_ID, 0x8909 --
        # and must not carry the mDNS-only cache-flush bit (also section 6.7).
        if grep -E "P qr=1 id=35081 dst=169\.254\.89\.2" >/dev/null "$q_log" &&
           grep -E "R qr=1 dst=169\.254\.89\.2 sec=an name=$REF_PUB_SERVICE\.local type=12 ttl=[0-9]+ flush=0 ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
               >/dev/null "$q_log"; then
            return 0
        fi
    done

    cat "$q_log" >&2
    return 1
}

ref_scenario_responder_legacy_ttl_cap() {
    : "Legacy replies should cap record TTLs at ten seconds (RFC 6762 section 6.7)"
    local q_log="$REF_TMPDIR/legacyttl.query"

    for _ in 1 2; do
        ref_query "$q_log" "$REF_PUB_SERVICE.local" --source-port 0 --duration 5 || return 2
        grep -E "R qr=1 dst=169\.254\.89\.2 .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
            >/dev/null "$q_log" && break
    done
    # Getting a reply at all is responder_legacy_unicast's business; none here
    # means the harness, not the TTL handling, is broken.
    grep -E "R qr=1 dst=169\.254\.89\.2 .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
        >/dev/null "$q_log" || { cat "$q_log" >&2; return 2; }

    # Records in a legacy reply end up in an ordinary unicast DNS cache that
    # never sees the goodbyes or cache-flush updates keeping mDNS caches
    # coherent, hence section 6.7: the TTL "SHOULD NOT be greater than ten
    # seconds". A SHOULD, so this is tracked as a deviation, not a violation.
    grep -E "R qr=1 dst=169\.254\.89\.2 sec=an name=$REF_PUB_SERVICE\.local type=12 ttl=([0-9]|10) flush=" \
        >/dev/null "$q_log" || { cat "$q_log" >&2; return 1; }
}

ref_scenario_responder_unicast_qu() {
    : "QU questions on recently multicast records are answered via unicast (RFC 6762 section 5.4)"
    local qm_log="$REF_TMPDIR/qm.query" qu_log="$REF_TMPDIR/qu.query"

    for _ in 1 2; do
        # First elicit a multicast answer, making the record recently
        # multicast. Only then is unicast the unambiguous conforming reply to
        # a QU question: section 5.4 tells a responder to instead multicast
        # the answer to a QU question if it has NOT multicast it within a
        # quarter of its TTL, to keep peer caches current.
        ref_query "$qm_log" "$REF_PUB_SERVICE.local" --duration 3 || return 2
        grep -E "R qr=1 dst=224\.0\.0\.251 .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
            >/dev/null "$qm_log" || continue

        ref_query "$qu_log" "$REF_PUB_SERVICE.local" --qu --duration 5 || return 2
        grep -E "R qr=1 dst=169\.254\.89\.2 .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
            >/dev/null "$qu_log" && return 0
    done

    cat "$qm_log" "$qu_log" >&2
    return 1
}

# Ask for the registered service while listing it as a known answer with a TTL
# below half the true one: section 7.1 only permits suppression at >= half, so
# a reachable, answering responder must reply to this. Used to bracket the
# silence probe below -- silence proves nothing if the responder is missing.
ref_kasup_control() {
    local log_file="${1:?}"

    for _ in 1 2; do
        ref_query "$log_file" "$REF_PUB_SERVICE.local" \
            --known-answer-ptr "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --known-answer-ttl 10 \
            --duration 5 || return 2
        grep -E "R qr=1 dst=[^ ]+ .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
            >/dev/null "$log_file" && return 0
    done

    cat "$log_file" >&2
    return 1
}

ref_scenario_responder_known_answer_suppression() {
    : "Queries listing our answer with a fresh TTL must not be answered (RFC 6762 section 7.1)"
    local q_log="$REF_TMPDIR/kasup.query"

    # Without this control, silence below would count as an unexpected pass of
    # this known-failing scenario on any lost datagram, failing the testcase.
    ref_kasup_control "$REF_TMPDIR/kasup.control" || return 2

    # Now with a fresh TTL (the full published 120s): any reply repeating the
    # known answer means suppression is not implemented.
    ref_query "$q_log" "$REF_PUB_SERVICE.local" \
        --known-answer-ptr "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --duration 5 || return 2

    if grep -E "R qr=1 dst=[^ ]+ .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" >/dev/null "$q_log"; then
        cat "$q_log" >&2
        return 1
    fi

    # Bracket the silence: on its own, the unanswered probe above is
    # indistinguishable from the responder having gone missing meanwhile.
    ref_kasup_control "$REF_TMPDIR/kasup.control2" || return 2
}

ref_write_pub_dnssd_file() {
    mkdir -p "$(dirname "$REF_PUB_DNSSD_FILE")"
    cat >"$REF_PUB_DNSSD_FILE" <<EOF
[Service]
Name=$REF_PUB_INSTANCE
Type=$REF_PUB_SERVICE
Port=42089
TxtText=ref=1
EOF
}

ref_start_listener() {
    local log_file="${1:?}" duration="${2:?}"
    local i

    ip netns exec "$REF_NS" python3 "$REF_PEER_PY" listen \
        --iface "${REF_IF1}p" --duration "$duration" >"$log_file" 2>&1 &

    REF_LISTENER_PID=$!

    # The listener logs LISTENING once it has joined the multicast group; wait
    # for that instead of sleeping a fixed second, so slow starts on loaded
    # runners cannot make it miss the traffic, and a listener that dies on
    # startup surfaces as a harness error rather than a bogus verdict.
    for ((i = 0; i < 50; i++)); do
        if grep "LISTENING" >/dev/null 2>&1 "$log_file"; then
            return 0
        fi
        sleep .2
    done

    return 1
}

# Did the capture see goodbyes (TTL=0) for the registered service? Either the
# instance's own records (SRV/TXT) or the enumeration PTR pointing at it count.
ref_saw_goodbye() {
    grep -E "R qr=1 dst=[^ ]+ sec=an name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=[0-9]+ ttl=0|R qr=1 dst=[^ ]+ sec=an .* type=12 ttl=0 flush=[01] ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
        >/dev/null "${1:?}"
}

ref_scenario_publisher_probe_announce() {
    : "resolved probes before announcing, and announces twice (RFC 6762 sections 8.1 and 8.3)"
    local listen_log="$REF_TMPDIR/pubannounce.listen"
    local announces

    ref_write_pub_dnssd_file || return 2
    ref_start_listener "$listen_log" 15 || return 2

    # Reload rather than restart: it re-runs the .dnssd loading logic while
    # leaving the runtime per-link mDNS switches intact.
    systemctl reload systemd-resolved.service || { kill "$REF_LISTENER_PID" 2>/dev/null || :; return 2; }
    wait "$REF_LISTENER_PID" || return 2

    # RFC 6762 section 8.1: the unique records must be probed for (a query for
    # the instance name carrying the proposed records in the authority
    # section), three times, 250ms apart -- the links are dedicated and
    # conflict-free, so all three probes must show up in the capture...
    local probes
    probes="$({ grep -c "Q name=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local .*probe=1" "$listen_log" || :; })"
    [[ "$probes" -ge 3 ]] || { cat "$listen_log" >&2; return 1; }
    # ...and section 8.3: the service must be announced at least twice.
    # Type 33 is SRV; a positive TTL distinguishes announcements from goodbyes.
    announces="$({ grep -cE "R qr=1 dst=[^ ]+ sec=an name=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local type=33 ttl=[1-9]" "$listen_log" || :; })"
    [[ "$announces" -ge 2 ]] || { cat "$listen_log" >&2; return 1; }
}

ref_scenario_publisher_unregister_goodbye() {
    : "Unregistering a service sends goodbyes for its records (RFC 6762 section 10.1)"
    local listen_log="$REF_TMPDIR/pubunreg.listen"

    # The service registered by publisher_probe_announce is still published.
    rm -f "$REF_PUB_DNSSD_FILE"
    ref_start_listener "$listen_log" 10 || return 2

    systemctl reload systemd-resolved.service || { kill "$REF_LISTENER_PID" 2>/dev/null || :; return 2; }
    wait "$REF_LISTENER_PID" || return 2

    ref_saw_goodbye "$listen_log" || { cat "$listen_log" >&2; return 1; }
}

ref_scenario_publisher_stop_goodbye() {
    : "Stopping resolved sends goodbyes for published services (RFC 6762 section 10.1, #30421)"
    # https://github.com/systemd/systemd/issues/30421
    local listen_log="$REF_TMPDIR/pubstop.listen"
    local rc=0

    ref_write_pub_dnssd_file || return 2
    systemctl reload systemd-resolved.service || return 2
    sleep 3  # let probing and announcing of the re-registered service finish

    ref_start_listener "$listen_log" 10 || return 2

    systemctl stop systemd-resolved.service || rc=2
    wait "$REF_LISTENER_PID" || rc=2

    # Bring resolved back up whatever happened above; a failure to restore is
    # a harness error that must fail the testcase, not later testcases.
    systemctl start systemd-resolved.service || return 2
    ref_restore_after_resolved_restart || return 2
    [[ "$rc" -eq 0 ]] || return "$rc"

    ref_saw_goodbye "$listen_log" || { cat "$listen_log" >&2; return 1; }
}

testcase_conformance_scorecard() {
    : "Score resolved's mDNS/DNS-SD conformance scenario by scenario"

    # Each entry is a TODO: a conformance gap this test tracks rather than
    # gates on, tagged with the requirement level it misses -- MUST is a
    # violation, SHOULD a deviation -- so the table doubles as a work list.
    local -A known_failures=(
        # The browser deduplicates discovered services by record content and
        # family only, ignoring the interface: same-name instances on multiple
        # links are collapsed into whichever link announced first, events for
        # the other links are swallowed, and a goodbye on one link is not
        # reported as long as any other link still carries the records.
        # https://github.com/OpenPrinting/libcups/issues/81#issuecomment-5122506798
        [two_interfaces_same_name]="TODO, reported: libcups#81 (issuecomment-5122506798)"
        [goodbye_one_interface]="TODO, reported: libcups#81 (issuecomment-5122506798)"
        # Without SD_RESOLVED_NO_STALE the per-service maintenance timer is
        # armed from a bogus cache expiry timestamp and dies after one shot, so
        # silently vanished publishers are never reported as removed.
        [expiry_no_goodbye_plain_flags]="TODO, MUST (RFC 6762 section 10): maintenance timer dies without SD_RESOLVED_NO_STALE"
        # Reloading drops deregistered .dnssd services from the registry
        # without withdrawing their records: no goodbyes are sent (and the
        # stale records even remain in the local zone).
        [publisher_unregister_goodbye]="TODO, SHOULD (RFC 6762 section 10.1): dnssd_registered_service_clear_on_reload() does not withdraw"
        # No goodbye packets are sent for published services on daemon stop.
        [publisher_stop_goodbye]="TODO, SHOULD (RFC 6762 section 10.1): no goodbyes on stop, see #30421"
        # mdns_scope_process_query never looks at the query's answer section,
        # so it re-answers queries that already carry the answer.
        [responder_known_answer_suppression]="TODO, MUST (RFC 6762 section 7.1): responder-side suppression not implemented, see the TODO in mdns_scope_process_query()"
        # Replies to legacy queries are built from the zone with the records'
        # full TTLs; nothing implements the ten-second cap.
        [responder_legacy_ttl_cap]="TODO, SHOULD (RFC 6762 section 6.7): legacy reply TTLs are not capped to ten seconds"
        # Every BrowseServices subscriber runs its own query engine, so wire
        # traffic scales with the subscriber count (known since the browser
        # was introduced, see the TODO in commit 8458b7fb91ea).
        [duplicate_question_suppression]="TODO, SHOULD (RFC 6762 section 7.3): one query engine per subscriber, see commit 8458b7fb91ea"
    )
    # Note: the order matters at the end of the list -- the responder_*
    # scenarios query the RefPub89 service that publisher_probe_announce
    # registers and publisher_unregister_goodbye deregisters again.
    local scenarios=(
        announce
        case_insensitive_match
        two_interfaces_same_name
        goodbye
        goodbye_one_interface
        expiry_no_goodbye
        expiry_no_goodbye_plain_flags
        querier_known_answers
        duplicate_question_suppression
        browse_subtype
        publisher_probe_announce
        responder_service_enumeration
        responder_legacy_unicast
        responder_legacy_ttl_cap
        responder_unicast_qu
        responder_known_answer_suppression
        publisher_unregister_goodbye
        publisher_stop_goodbye
    )
    local -A results=()
    local i scenario rc verdict=0

    # A previously interrupted run may have leaked the fixed-name namespace and
    # links (RETURN traps do not fire when set -e aborts a function mid-flight),
    # so clear them first to keep re-runs self-healing.
    ip netns del "$REF_NS" 2>/dev/null || :
    ip link del "$REF_IF1" 2>/dev/null || :
    ip link del "$REF_IF2" 2>/dev/null || :

    REF_TMPDIR="$(mktemp -d)"
    # An EXIT trap rather than RETURN: run_testcases executes each testcase in
    # its own subshell, and the subshell's EXIT trap also fires when errexit
    # aborts the setup below mid-flight -- a RETURN trap does not, and would
    # leak the tmpdir on an aborted setup (the fixed-name namespace and links
    # are covered by the self-healing removal above either way).
    trap ref_teardown EXIT
    ip netns add "$REF_NS"

    for i in 1 2; do
        local host_if="mdnsref$i" peer_if="mdnsref${i}p"
        ip link add "$host_if" type veth peer name "$peer_if" netns "$REF_NS"
        # Keep the expected event stream exact: IPv4 only.
        sysctl -qw "net.ipv6.conf.$host_if.disable_ipv6=1"
        ip netns exec "$REF_NS" sysctl -qw "net.ipv6.conf.$peer_if.disable_ipv6=1"
        ip link set "$host_if" up
        ip address add "169.254.$((88 + i)).1/24" dev "$host_if"
        ip -n "$REF_NS" link set "$peer_if" up
        ip -n "$REF_NS" address add "169.254.$((88 + i)).2/24" dev "$peer_if"
        resolvectl mdns "$host_if" yes
        [[ "$(resolvectl mdns "$host_if")" =~ :\ yes$ ]]
    done
    REF_IF1_INDEX="$(<"/sys/class/net/$REF_IF1/ifindex")"
    REF_IF2_INDEX="$(<"/sys/class/net/$REF_IF2/ifindex")"
    sleep 2  # let resolved create the scopes before we start browsing

    resolvectl flush-caches

    for scenario in "${scenarios[@]}"; do
        : "+++ scorecard scenario $scenario BEGIN +++"
        rc=0
        "ref_scenario_$scenario" || rc=$?
        ref_scenario_cleanup
        results[$scenario]=$rc
        : "+++ scorecard scenario $scenario END (rc=$rc) +++"
    done

    echo "=== mDNS/DNS-SD conformance scorecard ==="
    for scenario in "${scenarios[@]}"; do
        rc="${results[$scenario]}"
        printf '%-32s %s%s\n' "$scenario" \
            "$([[ "$rc" -eq 0 ]] && echo PASS || echo FAIL)" \
            "${known_failures[$scenario]:+ (known failure: ${known_failures[$scenario]})}"
    done

    for scenario in "${scenarios[@]}"; do
        rc="${results[$scenario]}"
        if [[ "$rc" -eq 0 && -n "${known_failures[$scenario]:-}" ]]; then
            echo >&2 "Scenario $scenario now passes: remove it from known_failures so it cannot regress"
            verdict=1
        elif [[ "$rc" -eq 1 && -z "${known_failures[$scenario]:-}" ]]; then
            echo >&2 "Scenario $scenario regressed"
            verdict=1
        elif [[ "$rc" -gt 1 ]]; then
            echo >&2 "Scenario $scenario failed with a harness error"
            verdict=1
        fi
    done

    return "$verdict"
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
