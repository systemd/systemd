#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# The containers, the bridge and its ifindex are set up by the main script.
CONTAINER_ZONE="${CONTAINER_ZONE:?}"
CONTAINER_1="${CONTAINER_1:?}"
CONTAINER_2="${CONTAINER_2:?}"
BRIDGE_INDEX="${BRIDGE_INDEX:?}"

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
REF_CONFLICT_DNSSD_FILE="/run/systemd/dnssd/refconflict.dnssd"
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

ref_resolve_ptr() {
    # Usage: ref_resolve_ptr <out_file> <name> <ifindex>
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveRecord \
        "{ \"name\": \"${2:?}\", \"class\": 1, \"type\": 12, \"ifindex\": ${3:?}, \"flags\": $REF_BROWSE_FLAGS }" \
        >"${1:?}" 2>&1
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
    rm -f "$REF_PUB_DNSSD_FILE" "$REF_CONFLICT_DNSSD_FILE"
    systemctl reload systemd-resolved.service 2>/dev/null || :

    rm -rf "$REF_TMPDIR"
}

# A freshly (re)started resolved may not have re-enumerated the links yet, so
# retry re-enabling mDNS/LLMNR on the container bridge for a bounded while.
ref_restore_after_resolved_restart() {
    local i

    for i in {0..19}; do
        if resolvectl mdns "vz-$CONTAINER_ZONE" on 2>/dev/null &&
           resolvectl llmnr "vz-$CONTAINER_ZONE" on 2>/dev/null &&
           resolvectl mdns "$REF_IF1" yes 2>/dev/null &&
           resolvectl mdns "$REF_IF2" yes 2>/dev/null; then
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
        ref_wait_listener || return 2
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
    ref_wait_listener || return 2
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

    ref_ensure_pub_service || return 2

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

    ref_ensure_pub_service || return 2

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

    ref_ensure_pub_service || return 2

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

    ref_ensure_pub_service || return 2

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

    ref_ensure_pub_service || return 2

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

ref_scenario_resolve_service() {
    : "A discovered service resolves to host, port and TXT (RFC 6763 section 5)"
    local out="$REF_TMPDIR/resolve.json"

    # The containers publish these; browsing only reports that an instance
    # exists, resolving it is the other half of DNS-SD.
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService \
        "{ \"name\": \"Test Service 0 on $CONTAINER_1\", \"type\": \"_testService0._udp\", \"domain\": \"local\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 1; }

    grep "\"port\":8010,\"hostname\":\"$CONTAINER_1.local\"" >/dev/null "$out" ||
        { cat "$out" >&2; return 1; }
    grep '"txt":\["DC=Device' >/dev/null "$out" || { cat "$out" >&2; return 1; }
}

ref_scenario_hostname_resolution() {
    : "A .local hostname resolves over mDNS (RFC 6762 section 3)"
    local out="$REF_TMPDIR/hostname.json"

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
        "{ \"name\": \"$CONTAINER_1.local\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 1; }
    grep '"address":\[' >/dev/null "$out" || { cat "$out" >&2; return 1; }
}

ref_scenario_reverse_lookup() {
    : "An address of an mDNS host reverse-resolves to its name (RFC 6762 section 3)"
    local fwd="$REF_TMPDIR/reverse.fwd" out="$REF_TMPDIR/reverse.json" family address

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
        "{ \"name\": \"$CONTAINER_1.local\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$fwd" 2>&1 || { cat "$fwd" >&2; return 2; }

    # Feed the address straight back in: the reply carries it as a byte array,
    # which is also how ResolveAddress wants it.
    family="$({ grep -oE '"family":[0-9]+' "$fwd" || :; } | head -1 | cut -d: -f2)"
    address="$({ grep -oE '"address":\[[0-9,]+\]' "$fwd" || :; } | head -1 | cut -d: -f2-)"
    [[ -n "$family" && -n "$address" ]] || { cat "$fwd" >&2; return 2; }

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveAddress \
        "{ \"family\": $family, \"address\": $address, \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 1; }
    grep "$CONTAINER_1" >/dev/null "$out" || { cat "$out" >&2; return 1; }
}

ref_scenario_publisher_subtype() {
    : "A service published with a subtype is found by a subtype browse (RFC 6763 section 7.1)"
    local out="$REF_TMPDIR/pubsub.browse" rc=0

    systemd-run -M "$CONTAINER_1" --wait --pipe -- tee /etc/systemd/dnssd/subtype-canary.dnssd <<EOF || return 2
[Service]
Name=Subtype Canary on %H
Type=_testSubtype._udp
SubType=_vendor
Port=8011
TxtText=DC=Device
EOF
    systemd-run -M "$CONTAINER_1" --wait --pipe -- systemctl reload systemd-resolved.service || return 2

    ref_start_browse "$out" "${BRIDGE_INDEX:?}" "" "_vendor._sub._testSubtype._udp.local" || return 2
    ref_wait_added_name "$out" "Subtype Canary on $CONTAINER_1" 30 || { cat "$out" >&2; rc=1; }

    systemd-run -M "$CONTAINER_1" --wait --pipe -- rm -f /etc/systemd/dnssd/subtype-canary.dnssd || :
    systemd-run -M "$CONTAINER_1" --wait --pipe -- systemctl reload systemd-resolved.service || :
    return "$rc"
}

ref_scenario_conflict_rename() {
    : "A lost probe tiebreak is resolved by picking a new name (RFC 6762 section 9)"
    local listen_log="$REF_TMPDIR/conflict.listen" peer_log="$REF_TMPDIR/conflict.peer"
    local conflict_file="$REF_CONFLICT_DNSSD_FILE" rc=0

    # The peer defends the instance name resolved is about to claim. Give the
    # peer the higher port so it wins the section 8.2 lexicographic tiebreak
    # deterministically: resolved must then rename rather than go silent.
    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefConflict --service _refconf._udp || return 2
    sleep 2

    mkdir -p "$(dirname "$conflict_file")"
    cat >"$conflict_file" <<EOF
[Service]
Name=RefConflict
Type=_refconf._udp
Port=100
EOF
    ref_start_listener "$listen_log" 20 || { rm -f "$conflict_file"; return 2; }
    systemctl reload systemd-resolved.service || { rm -f "$conflict_file"; return 2; }
    ref_wait_listener || rc=2

    rm -f "$conflict_file"
    systemctl reload systemd-resolved.service || :
    [[ "$rc" -eq 0 ]] || return "$rc"

    # Positive control: resolved must have probed for the contested name.
    grep "Q name=RefConflict._refconf._udp.local .*probe=1" >/dev/null "$listen_log" ||
        { cat "$listen_log" "$peer_log" >&2; return 2; }

    # Having lost, it must claim a different name -- an announcement of an SRV
    # under the same type whose owner is not the contested name.
    grep -E "R qr=1 dst=[^ ]+ sec=an name=[^ ]+\._refconf\._udp\.local type=33 ttl=[1-9]" "$listen_log" |
        grep -v "name=RefConflict\._refconf\._udp\.local" >/dev/null ||
        { cat "$listen_log" >&2; return 1; }
}

ref_scenario_cache_flush_update() {
    : "A re-announced unique record replaces the cached one (RFC 6762 section 10.2)"
    local peer_log="$REF_TMPDIR/flush.peer" out="$REF_TMPDIR/flush.json"

    ref_start_peer "$peer_log" "${REF_IF1}p" 169.254.89.2 RefFlush --service _refflush._udp --port 41001 || return 2
    sleep 4
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService \
        "{ \"name\": \"RefFlush\", \"type\": \"_refflush._udp\", \"domain\": \"local\", \"ifindex\": $REF_IF1_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 2; }
    grep '"port":41001' >/dev/null "$out" || { cat "$out" >&2; return 2; }

    # Same instance, new port, announced with the cache-flush bit set.
    kill -KILL "$REF_LAST_PEER_PID" || return 2
    ref_start_peer "$peer_log.2" "${REF_IF1}p" 169.254.89.2 RefFlush --service _refflush._udp --port 41002 || return 2
    sleep 4

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService \
        "{ \"name\": \"RefFlush\", \"type\": \"_refflush._udp\", \"domain\": \"local\", \"ifindex\": $REF_IF1_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 2; }
    grep '"port":41002' >/dev/null "$out" || { cat "$out" "$peer_log.2" >&2; return 1; }
}

ref_scenario_shared_record_response_delay() {
    : "Responses to shared records are delayed 20-120ms (RFC 6762 section 6)"
    local q_log="$REF_TMPDIR/delay.query" delay

    ref_ensure_pub_service || return 2

    # The PTR of a registered service is a shared record, so the response is
    # supposed to be spread over 20-120ms rather than sent immediately.
    ref_query "$q_log" "$REF_PUB_SERVICE.local" --duration 5 || return 2
    grep -E "R qr=1 .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 2; }

    delay="$(awk '/ QUERY name=/ { q = $1 } / R qr=1 .* ptr=/ && q != "" { printf "%d\n", ($1 - q) * 1000; exit }' "$q_log")"
    [[ -n "$delay" ]] || { cat "$q_log" >&2; return 2; }
    [[ "$delay" -ge 20 ]] || { echo >&2 "answered after ${delay}ms"; return 1; }
}

ref_scenario_known_answer_continuation() {
    : "Known answers in a follow-up packet suppress the reply (RFC 6762 section 7.2)"
    local q_log="$REF_TMPDIR/kacont.query"

    ref_ensure_pub_service || return 2

    # Same bracketing as the single-packet suppression scenario: prove the
    # responder answers at all, so silence below means suppression.
    ref_kasup_control "$REF_TMPDIR/kacont.control" || return 2

    # TC set, known answer in a second packet: the responder is supposed to
    # defer 400-500ms, collect it, and then stay quiet.
    ref_query "$q_log" "$REF_PUB_SERVICE.local" --tc --followup-known-answer \
        --known-answer-ptr "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --duration 5 || return 2

    if grep -E "R qr=1 dst=[^ ]+ .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" >/dev/null "$q_log"; then
        cat "$q_log" >&2
        return 1
    fi
}

ref_scenario_multi_interface_ptr_query() {
    : "A query across all interfaces returns the services of every interface (#38380)"
    local peer1_log="$REF_TMPDIR/multi.peer1" peer2_log="$REF_TMPDIR/multi.peer2"
    local out="$REF_TMPDIR/multi.rr"

    ref_start_peer "$peer1_log" "${REF_IF1}p" 169.254.89.2 RefIf1 --service _refmulti._udp || return 2
    ref_start_peer "$peer2_log" "${REF_IF2}p" 169.254.90.2 RefIf2 --service _refmulti._udp || return 2
    sleep 5

    # Positive control: each publisher answers on its own interface, so
    # anything missing below is the combining, not the publisher.
    ref_resolve_ptr "$out.1" _refmulti._udp.local "$REF_IF1_INDEX" || return 2
    grep RefIf1 >/dev/null "$out.1" || { cat "$out.1" "$peer1_log" >&2; return 2; }
    ref_resolve_ptr "$out.2" _refmulti._udp.local "$REF_IF2_INDEX" || return 2
    grep RefIf2 >/dev/null "$out.2" || { cat "$out.2" "$peer2_log" >&2; return 2; }

    ref_resolve_ptr "$out.0" _refmulti._udp.local 0 || return 2
    if ! grep RefIf1 >/dev/null "$out.0" || ! grep RefIf2 >/dev/null "$out.0"; then
        cat "$out.0" >&2
        return 1
    fi
}

ref_scenario_dual_stack_resolution() {
    : "A hostname query returns both address families, not just one (#25855)"
    local out="$REF_TMPDIR/dualstack.json"

    local family

    # Controls: both families resolve when asked for by name, so anything
    # missing below is the combining of the two, not the publisher.
    for family in 2 10; do
        varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
            "{ \"name\": \"$CONTAINER_1.local\", \"family\": $family, \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": $REF_BROWSE_FLAGS }" \
            >"$out.$family" 2>&1 || { cat "$out.$family" >&2; return 2; }
        grep "\"family\":$family" >/dev/null "$out.$family" || { cat "$out.$family" >&2; return 2; }
    done

    # Asking for neither in particular has to yield both.
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
        "{ \"name\": \"$CONTAINER_1.local\", \"ifindex\": ${BRIDGE_INDEX:?}, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 2; }

    grep '"family":2' >/dev/null "$out" || { cat "$out" >&2; return 1; }
    grep '"family":10' >/dev/null "$out" || { cat "$out" >&2; return 1; }
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

# Waits for the listener to finish and forgets it, so the cleanup below never
# signals a pid that has already been reaped -- and possibly reused since.
ref_wait_listener() {
    local pid="$REF_LISTENER_PID"

    REF_LISTENER_PID=""
    [[ -n "$pid" ]] || return 0
    wait "$pid"
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

# The scenarios that query resolved's own published service each make sure it
# is there, rather than relying on the order they run in.
ref_ensure_pub_service() {
    [[ -e "$REF_PUB_DNSSD_FILE" ]] && return 0

    ref_write_pub_dnssd_file || return 2
    systemctl reload systemd-resolved.service || return 2
    sleep 3  # let probing and announcing finish
}

ref_unpublish_pub_service() {
    rm -f "$REF_PUB_DNSSD_FILE"
    systemctl reload systemd-resolved.service || return 2
}

ref_scenario_publisher_probe_announce() {
    : "resolved probes before announcing, and announces twice (RFC 6762 sections 8.1 and 8.3)"
    local listen_log="$REF_TMPDIR/pubannounce.listen"
    local announces probes

    # The burst happens once per registration, so retrying means registering
    # again, not just looking at the same capture a second time.
    for _ in 1 2; do
        # Start from unregistered, so the reload really probes and announces.
        ref_unpublish_pub_service || return 2
        ref_start_listener "$listen_log" 15 || return 2
        ref_write_pub_dnssd_file || return 2

        # Reload rather than restart: it re-runs the .dnssd loading logic while
        # leaving the runtime per-link mDNS switches intact.
        systemctl reload systemd-resolved.service || { kill "$REF_LISTENER_PID" 2>/dev/null || :; return 2; }
        ref_wait_listener || return 2

        # RFC 6762 section 8.1: the unique records must be probed for (a query
        # for the instance name carrying the proposed records in the authority
        # section), three times, 250ms apart -- the links are dedicated and
        # conflict-free, so all three probes must show up in the capture...
        probes="$({ grep -c "Q name=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local .*probe=1" "$listen_log" || :; })"
        # ...and section 8.3: the service must be announced at least twice.
        # Type 33 is SRV; a positive TTL tells announcements from goodbyes.
        announces="$({ grep -cE "R qr=1 dst=[^ ]+ sec=an name=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local type=33 ttl=[1-9]" "$listen_log" || :; })"
        [[ "$probes" -ge 3 && "$announces" -ge 2 ]] && return 0
    done

    cat "$listen_log" >&2
    return 1
}

ref_scenario_publisher_unregister_goodbye() {
    : "Unregistering a service sends goodbyes for its records (RFC 6762 section 10.1)"
    local listen_log="$REF_TMPDIR/pubunreg.listen"

    ref_ensure_pub_service || return 2
    rm -f "$REF_PUB_DNSSD_FILE"
    ref_start_listener "$listen_log" 10 || return 2

    systemctl reload systemd-resolved.service || { kill "$REF_LISTENER_PID" 2>/dev/null || :; return 2; }
    ref_wait_listener || return 2

    ref_saw_goodbye "$listen_log" || { cat "$listen_log" >&2; return 1; }
}

ref_scenario_publisher_stop_goodbye() {
    : "Stopping resolved sends goodbyes for published services (RFC 6762 section 10.1, #30421)"
    # https://github.com/systemd/systemd/issues/30421
    local listen_log="$REF_TMPDIR/pubstop.listen"
    local rc=0

    ref_ensure_pub_service || return 2

    ref_start_listener "$listen_log" 10 || return 2

    systemctl stop systemd-resolved.service || rc=2
    ref_wait_listener || rc=2

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
        # dns_zone_item_conflict() withdraws the record and signals the D-Bus
        # client instead of picking a new name, so a service published from a
        # .dnssd file simply disappears when another host defends the name.
        # Reported in #38380: only the services of one interface come back.
        [multi_interface_ptr_query]="TODO (#38380): a query on all interfaces returns only one interface's services"
        # Reported in #19003 and #25855: the answer carries one family only,
        # although each family resolves when asked for by name.
        [dual_stack_resolution]="TODO (#25855): a hostname query returns one address family, not both"
        [conflict_rename]="TODO, MUST (RFC 6762 section 9): a lost tiebreak withdraws the name instead of renaming"
        [shared_record_response_delay]="TODO, SHOULD (RFC 6762 section 6): shared-record responses are sent immediately"
        # Reported in #14119: the follow-up packet carries no question, so
        # mdns_scope_process_query() drops it and answers anyway.
        [known_answer_continuation]="TODO (RFC 6762 section 7.2): known answers in a follow-up packet are ignored, see #14119"
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
    # Ordered by the requirement each one checks: RFC 6762 by section, then
    # RFC 6763, then the ones whose only basis is a report. The scenarios do
    # not depend on each other or on this order.
    local scenarios=(
        announce                            # baseline
        hostname_resolution                 # 6762 section 3
        reverse_lookup                      # 6762 section 3
        responder_unicast_qu                # 6762 section 5.4
        shared_record_response_delay        # 6762 section 6
        responder_legacy_unicast            # 6762 section 6.7
        responder_legacy_ttl_cap            # 6762 section 6.7
        querier_known_answers               # 6762 section 7.1
        responder_known_answer_suppression  # 6762 section 7.1
        known_answer_continuation           # 6762 section 7.2
        duplicate_question_suppression      # 6762 section 7.3
        publisher_probe_announce            # 6762 sections 8.1 and 8.3
        conflict_rename                     # 6762 section 9
        expiry_no_goodbye                   # 6762 section 10
        expiry_no_goodbye_plain_flags       # 6762 section 10
        goodbye                             # 6762 section 10.1
        publisher_unregister_goodbye        # 6762 section 10.1
        publisher_stop_goodbye              # 6762 section 10.1
        cache_flush_update                  # 6762 section 10.2
        case_insensitive_match              # 6762 section 16
        resolve_service                     # 6763 section 5
        browse_subtype                      # 6763 section 7.1
        publisher_subtype                   # 6763 section 7.1
        responder_service_enumeration       # 6763 section 9
        two_interfaces_same_name            # libcups#81
        goodbye_one_interface               # libcups#81
        dual_stack_resolution               # #19003, #25855
        multi_interface_ptr_query           # #38380
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

run_testcases
