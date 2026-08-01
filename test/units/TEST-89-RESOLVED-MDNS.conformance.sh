#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# The containers, the bridge and its ifindex are set up by the main script.
CONTAINER_ZONE="${CONTAINER_ZONE:?}"
CONTAINER_1="${CONTAINER_1:?}"
BRIDGE_INDEX="${BRIDGE_INDEX:?}"
FIXTURE_SERVICE_INSTANCE="${FIXTURE_SERVICE_INSTANCE:?}"
FIXTURE_SERVICE_TYPE="${FIXTURE_SERVICE_TYPE:?}"
FIXTURE_SERVICE_PORT="${FIXTURE_SERVICE_PORT:?}"

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
# Unlike the container-based testcases in TEST-89-RESOLVED-MDNS.sh, these talk to
# publishers that we control at the packet level (dedicated veth pairs into a
# network namespace), so they can exercise behavior that well-behaved
# publishers never trigger: same-name announcements from multiple interfaces,
# goodbye-less disappearance, per-interface goodbyes, etc. IPv6 is disabled on
# the test links to keep the expected event stream exact (family 2 only).

REF_NS="mdnsref"
REF_IF1="mdnsref1"
REF_IF2="mdnsref2"
# The namespace ends of the links, named here so both ends of each link come
# from one place -- the setup loop below consumes these rather than re-deriving
# the suffix.
REF_IF1_PEER="${REF_IF1}p"
REF_IF2_PEER="${REF_IF2}p"
# The addresses the setup loop below assigns to the namespace ends of the links.
REF_IF1_PEER_ADDR="169.254.89.2"
REF_IF2_PEER_ADDR="169.254.90.2"
# The same address as an extended regex, for matching it in captured packets.
REF_IF1_PEER_ADDR_RE="${REF_IF1_PEER_ADDR//./\\.}"
REF_SERVICE="_ref._udp"
REF_PUB_SERVICE="_refpub._udp"
REF_PUB_INSTANCE="RefPub89"
REF_PUB_DNSSD_FILE="/run/systemd/dnssd/refpub89.dnssd"
REF_CONFLICT_DNSSD_FILE="/run/systemd/dnssd/refconflict.dnssd"
REF_PROBE_DNSSD_FILE="/run/systemd/dnssd/refprobe.dnssd"
REF_EST_DNSSD_FILE="/run/systemd/dnssd/refest.dnssd"
REF_PEER_PY="$(dirname "$0")/TEST-89-RESOLVED-MDNS.peer.py"
# SD_RESOLVED_MDNS_IPV4|SD_RESOLVED_MDNS_IPV6|SD_RESOLVED_NO_ZONE|SD_RESOLVED_NO_STALE, i.e. what
# the testcases in TEST-89-RESOLVED-MDNS.sh pass -- taken from the parent's export so the two
# files cannot drift apart.
REF_BROWSE_FLAGS="${BROWSE_SERVICE_FLAGS:?}"
# The same minus SD_RESOLVED_NO_STALE (1 << 24): what a plain external client
# that does not know about resolved-internal staleness handling would pass.
REF_BROWSE_FLAGS_PLAIN=$((REF_BROWSE_FLAGS & ~(1 << 24)))
# The same as REF_BROWSE_FLAGS plus SD_RESOLVED_NO_CACHE (1 << 12).
REF_BROWSE_FLAGS_NO_CACHE=$((REF_BROWSE_FLAGS | (1 << 12)))
# QUERY_ID in TEST-89-RESOLVED-MDNS.peer.py (0x8909), the transaction ID it
# stamps on legacy queries, which RFC 6762 section 6.7 makes the reply echo.
REF_PEER_QUERY_ID=35081

REF_PEER_PIDS=()
REF_BROWSE_UNITS=()
REF_LAST_PEER_PID=""
REF_LISTENER_PID=""
REF_TMPDIR=""
REF_IF1_INDEX=""
REF_IF2_INDEX=""

# Count browse events in a JSON-SEQ output file. The events are split into one
# object per line first and every field is then matched on its own: the key
# order in resolved's reply is an artifact of its serializer, not interface
# contract, so nothing here may depend on adjacency or sequence. IPv6 is
# disabled on the reference links, hence no per-family disambiguation is
# needed.
# The single place that knows how a browse notification is shaped: split the
# reply into JSON objects and keep the ones matching every extended regex given.
# Splitting on '{...}' assumes browserServiceData entries carry no nested
# objects, which is exactly why it lives in one helper rather than at each site.
ref_match_events() {
    local file="${1:?}"
    local matches
    shift

    matches="$(grep -oE '\{[^{}]*\}' "$file" || :)"
    while (($#)); do
        matches="$(grep -E "$1" <<<"$matches" || :)"
        shift
    done

    printf '%s' "$matches"
}

ref_count_events() {
    local file="${1:?}" flag="${2:?}" instance="${3:?}" ifindex="${4:-}"
    local matches
    local -a patterns=(
        "\"updateFlag\":\"$flag\""
        "\"name\":\"$instance\""
        "\"type\":\"$REF_SERVICE\""
        "\"domain\":\"local\""
    )

    if [[ -n "$ifindex" ]]; then
        patterns+=("\"ifindex\":${ifindex}[,}]")
    fi

    matches="$(ref_match_events "$file" "${patterns[@]}")"

    if [[ -z "$matches" ]]; then
        echo 0
    else
        wc -l <<<"$matches"
    fi
}

# Wait for at least $6 (default 1) matching events to show up in the browse output.
ref_wait_event() {
    local file="${1:?}" flag="${2:?}" instance="${3:?}" ifindex="${4:-}" iterations="${5:?}" count="${6:-1}"
    local i

    for ((i = 0; i < iterations; i++)); do
        [[ "$(ref_count_events "$file" "$flag" "$instance" "$ifindex")" -ge "$count" ]] && return 0
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
        if [[ -n "$(ref_match_events "$file" "\"updateFlag\":\"added\"" "\"name\":\"$instance\"")" ]]; then
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
    # 45s idle timeout, see the comments in TEST-89-RESOLVED-MDNS.sh.
    systemd-run --unit="$unit" --service-type=exec -p StandardOutput="file:$out_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "{ \"domain\": \"$domain\", \"type\": \"\", \"ifindex\": $ifindex, \"flags\": $flags }" || return 2

    REF_BROWSE_UNITS+=("$unit")
}

ref_resolve_ptr() {
    local out_file="${1:?}" name="${2:?}" ifindex="${3:?}" flags="${4:-$REF_BROWSE_FLAGS}"

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveRecord \
        "{ \"name\": \"$name\", \"class\": 1, \"type\": 12, \"ifindex\": $ifindex, \"flags\": $flags }" \
        >"$out_file" 2>&1
}

ref_query() {
    # Usage: ref_query <log_file> <qname> [extra peer args...]
    local log_file="${1:?}" qname="${2:?}"
    shift 2

    ip netns exec "$REF_NS" python3 "$REF_PEER_PY" query \
        --iface "$REF_IF1_PEER" --qname "$qname" "$@" >"$log_file" 2>&1
}

ref_start_peer() {
    local log_file="${1:?}" iface="${2:?}" addr="${3:?}" instance="${4:?}"
    shift 4
    local i

    # Truncate in the parent, so waiting for the readiness marker below cannot
    # match a previous publisher's line.
    : >"$log_file"
    ip netns exec "$REF_NS" python3 "$REF_PEER_PY" publish \
        --iface "$iface" --addr "$addr" --instance "$instance" --service "$REF_SERVICE" \
        --hostname "refpeer-$iface.local" "$@" >>"$log_file" 2>&1 &

    REF_LAST_PEER_PID=$!
    REF_PEER_PIDS+=("$REF_LAST_PEER_PID")

    # Wait until the publisher has sent all of its announcements. Scenarios
    # that kill a publisher would otherwise race the announcing burst, and a
    # goodbye that overtakes an announcement is a different thing to score.
    for ((i = 0; i < 100; i++)); do
        grep "ANNOUNCED" >/dev/null "$log_file" && return 0
        sleep .2
    done

    cat "$log_file" >&2
    return 1
}

# Reset all per-scenario state: peers, browse subscriptions, caches.
ref_cleanup_scenario_state() {
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
    ref_cleanup_scenario_state

    # Before the links go away: the restore below re-enables mDNS on them.
    if ! systemctl is-active systemd-resolved.service >/dev/null; then
        systemctl start systemd-resolved.service 2>/dev/null || :
        ref_restore_after_resolved_restart || :
    fi

    ip netns del "$REF_NS" 2>/dev/null || :
    ip link del "$REF_IF1" 2>/dev/null || :
    ip link del "$REF_IF2" 2>/dev/null || :
    rm -f "$REF_PUB_DNSSD_FILE" "$REF_CONFLICT_DNSSD_FILE" "$REF_PROBE_DNSSD_FILE" "$REF_EST_DNSSD_FILE"
    systemctl reload systemd-resolved.service 2>/dev/null || :

    rm -rf "$REF_TMPDIR"
}

# A freshly (re)started resolved may not have re-enumerated the links yet, so
# retry re-enabling mDNS/LLMNR on the container bridge for a bounded while.
ref_restore_after_resolved_restart() {
    local i

    for ((i = 0; i < 20; i++)); do
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

# Did the responder answer the witness question that rode along in the same
# packet (see --witness-qname)? That answer is what proves the query arrived,
# so that silence on the question under test means the responder chose to stay
# silent rather than never having heard it.
ref_saw_witness() {
    grep -E "R qr=1 dst=[^ ]+ sec=an name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=33" \
        >/dev/null "${1:?}"
}

# Send a query carrying both a known answer for the service PTR and a witness
# question, retrying until the witness comes back. Returns 2 if it never does.
ref_query_with_witness() {
    local log_file="${1:?}"
    shift
    local i

    for ((i = 0; i < 3; i++)); do
        ref_query "$log_file" "$REF_PUB_SERVICE.local" \
            --known-answer-ptr "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" \
            --witness-qname "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" \
            --duration 5 "$@" || return 2
        ref_saw_witness "$log_file" && return 0
    done

    cat "$log_file" >&2
    return 2
}

# A legacy query is answered by unicast to the ephemeral port it came from.
# Getting a reply at all is responder_legacy_unicast's business, so the two
# scenarios that go on to score something about that reply share this, and
# treat its absence as a harness error rather than as their own verdict.
ref_get_legacy_reply() {
    local log_file="${1:?}"
    local _

    for _ in 1 2; do
        ref_query "$log_file" "$REF_PUB_SERVICE.local" --source-port 0 --duration 5 || return 2
        grep -E "R qr=1 dst=$REF_IF1_PEER_ADDR_RE .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
            >/dev/null "$log_file" && return 0
    done

    cat "$log_file" >&2
    return 2
}

# Write a .dnssd service file for resolved to pick up on the next reload. The
# removal traps stay at the call sites: a RETURN trap armed here would already
# fire when this helper returns.
ref_write_dnssd_file() {
    local file="${1:?}" name="${2:?}" type="${3:?}" port="${4:?}" txt="${5:-}"

    mkdir -p "$(dirname "$file")"
    cat >"$file" <<EOF
[Service]
Name=$name
Type=$type
Port=$port
${txt:+TxtText=$txt}
EOF
}

ref_write_pub_dnssd_file() {
    ref_write_dnssd_file "$REF_PUB_DNSSD_FILE" "$REF_PUB_INSTANCE" "$REF_PUB_SERVICE" 42089 ref=1
}

# Waits for the listener to finish and forgets it, so the cleanup below never
# signals a pid that has already been reaped -- and possibly reused since.
ref_wait_listener() {
    local pid="$REF_LISTENER_PID"

    REF_LISTENER_PID=""
    [[ -n "$pid" ]] || return 0
    wait "$pid"
}

# A capture the peer could not fully decode must not back an absence verdict:
# a MALFORMED packet logs none of its lines and a MALFORMED-RECORD stops that
# packet's record lines where it hit, so the pattern whose absence would count
# as a PASS may be exactly what was lost. Harness error, not a verdict.
ref_capture_fully_decoded() {
    if grep "MALFORMED" >/dev/null "${1:?}"; then
        cat "$1" >&2
        return 2
    fi
}

# Liveness canary for absence verdicts on a listener capture: multicast loops back to local
# group members, so the marker query must show up -- a zero count from a deaf or dead listener
# reads as a harness error, never as conformance. Winds the listener down, so it comes last.
# Why each capture needs it stays with the call sites.
ref_marker_canary() {
    local marker_file="${1:?}" listen_log="${2:?}"

    ref_query "$marker_file" "refmark._udp.local" --duration 1 || return 2
    ref_wait_listener || return 2
    ref_capture_fully_decoded "$listen_log" || return 2
    grep "Q name=refmark._udp.local" >/dev/null "$listen_log" || { cat "$listen_log" >&2; return 2; }
}

# Did one response packet carry both records? Records are logged under the packet that carried
# them, so this is what "aggregated" and "answered together" mean on the wire -- two matches
# scraped from different packets in the window do not qualify.
ref_same_packet() {
    local log_file="${1:?}" a="${2:?}" b="${3:?}"

    awk -v a="$a" -v b="$b" '
        / P qr=1 / { seen_a = 0; seen_b = 0 }
        / R qr=1 / {
            if (index($0, a)) seen_a = 1
            if (index($0, b)) seen_b = 1
            if (seen_a && seen_b) { together = 1; exit }
        }
        END { exit together ? 0 : 1 }' "$log_file"
}

ref_start_listener() {
    local log_file="${1:?}" duration="${2:?}"
    local i

    # Truncate here rather than leaving it to the backgrounded child: a retry
    # reusing this file must not match the previous attempt's readiness line.
    : >"$log_file"
    ip netns exec "$REF_NS" python3 "$REF_PEER_PY" listen \
        --iface "$REF_IF1_PEER" --duration "$duration" >>"$log_file" 2>&1 &

    REF_LISTENER_PID=$!

    # The listener logs LISTENING once it has joined the multicast group; wait
    # for that instead of sleeping a fixed second, so slow starts on loaded
    # runners cannot make it miss the traffic, and a listener that dies on
    # startup surfaces as a harness error rather than a bogus verdict.
    for ((i = 0; i < 50; i++)); do
        if grep "LISTENING" >/dev/null "$log_file"; then
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

# Scenario exit codes: 0 = pass, 1 = tracked conformance failure,
# anything else = broken test harness (always fails the testcase).

ref_scenario_announce() {
    : "Baseline: one publisher, exactly one added event, none removed while it stays up"
    local out="$REF_TMPDIR/announce.browse" peer_log="$REF_TMPDIR/announce.peer"

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefAnnounce || return 2

    ref_wait_event "$out" added RefAnnounce "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 1; }

    # Quiet window: several continuous-query revisits happen, and the peer
    # keeps answering them, so nothing may be added again or removed.
    sleep 5
    # Positive control first: a peer that died right after announcing leaves the cached record
    # valid for its full TTL, and the counts below would pass having verified nothing past the
    # first announcement.
    kill -0 "$REF_LAST_PEER_PID" 2>/dev/null || { cat "$out" "$peer_log" >&2; return 2; }
    [[ "$(ref_count_events "$out" added RefAnnounce)" -eq 1 ]] || { cat "$out" "$peer_log" >&2; return 1; }
    [[ "$(ref_count_events "$out" removed RefAnnounce)" -eq 0 ]] || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_hostname_resolution() {
    : "A .local hostname resolves over mDNS (RFC 6762 section 3)"
    local out="$REF_TMPDIR/hostname.json"

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
        "{ \"name\": \"$CONTAINER_1.local\", \"ifindex\": $BRIDGE_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 1; }
    grep '"address":\[' >/dev/null "$out" || { cat "$out" >&2; return 1; }
}

ref_scenario_reverse_lookup() {
    : "An address of an mDNS host reverse-resolves to its name (RFC 6762 section 4)"
    local fwd="$REF_TMPDIR/reverse.fwd" out="$REF_TMPDIR/reverse.json" family address

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
        "{ \"name\": \"$CONTAINER_1.local\", \"ifindex\": $BRIDGE_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$fwd" 2>&1 || { cat "$fwd" >&2; return 2; }

    # Feed the address straight back in: the reply carries it as a byte array,
    # which is also how ResolveAddress wants it.
    family="$({ grep -oE '"family":[0-9]+' "$fwd" || :; } | head -1 | cut -d: -f2)"
    address="$({ grep -oE '"address":\[[0-9,]+\]' "$fwd" || :; } | head -1 | cut -d: -f2-)"
    [[ -n "$family" && -n "$address" ]] || { cat "$fwd" >&2; return 2; }

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveAddress \
        "{ \"family\": $family, \"address\": $address, \"ifindex\": $BRIDGE_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 1; }
    grep "$CONTAINER_1" >/dev/null "$out" || { cat "$out" >&2; return 1; }
}

ref_scenario_reverse_lookup_non_local() {
    : "An address outside the link is not asked for over mDNS (RFC 6762 section 4)"
    local listen_log="$REF_TMPDIR/nonlocal.listen" out="$REF_TMPDIR/nonlocal.json"

    ref_start_listener "$listen_log" 8 || return 2
    # 8.8.8.8 is in neither the link-local reverse zone nor the link's subnet,
    # so resolved must not reach for mDNS on its own. Ask without pinning a
    # link and without the mDNS flags -- forcing those would make it honour
    # the request, which is not what is being checked. Whether the lookup
    # itself succeeds depends on the DNS configuration and does not matter.
    #
    # This reproduces the mDNS half of #20267: alongside the unicast attempt,
    # resolved puts the same question to the mDNS group on every mDNS link.
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveAddress \
        "{ \"family\": 2, \"address\": [8,8,8,8], \"flags\": 0 }" \
        >"$out" 2>&1 || :
    # Without the canary, a listener that never joined the group would read as a conforming
    # resolved the moment the #20267 known-failure entry is gone.
    ref_marker_canary "$REF_TMPDIR/nonlocal.marker" "$listen_log" || return 2

    if grep "8.8.8.8.in-addr.arpa" >/dev/null "$listen_log"; then
        cat "$listen_log" >&2
        return 1
    fi
}

# A publisher is started, discovered, then killed; the instance has to be reported gone. $3 picks
# how it dies and how long the removal may take: SIGKILL with no goodbye leaves the querier to
# notice the 20s TTL lapse, while a goodbye-on-exit publisher has to be acted on within seconds.
ref_expiry_scenario() {
    local prefix="${1:?}" instance="${2:?}" mode="${3:?}" flags="${4:?}"
    shift 4
    local out="$REF_TMPDIR/$prefix.browse" peer_log="$REF_TMPDIR/$prefix.peer"
    local peer_args sig wait_secs

    # One place decides what each mode means, and an unrecognised mode is a harness error --
    # not a fallback branch quietly scoring a verdict for behaviour nobody meant to test.
    case "$mode" in
        goodbye)
            # RFC 6762 section 10.1: queriers delete goodbyed records after one second.
            peer_args=(--goodbye-on-exit)
            sig=TERM
            wait_secs=30
            ;;
        silent)
            # Vanish abruptly: no goodbye, and nobody answers re-confirmation queries. The
            # records carried a 20s TTL, so a conforming querier removes the service within
            # ~20s of the last answer; poll generously.
            peer_args=(--ttl 20)
            sig=KILL
            wait_secs=60
            ;;
        *)
            echo >&2 "unknown expiry mode '$mode'"
            return 2
            ;;
    esac

    ref_start_browse "$out" "$REF_IF1_INDEX" "$flags" || return 2
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" "$instance" "${peer_args[@]}" "$@" || return 2
    ref_wait_event "$out" added "$instance" "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 2; }

    kill "-$sig" "$REF_LAST_PEER_PID" || return 2
    ref_wait_event "$out" removed "$instance" "$REF_IF1_INDEX" "$wait_secs" || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_expiry_no_goodbye() {
    : "A publisher vanishing without goodbye is removed when its records expire (RFC 6762 section 5.2)"
    ref_expiry_scenario expiry RefExpiry silent "$REF_BROWSE_FLAGS"
}

ref_scenario_expiry_no_goodbye_plain_flags() {
    : "Silent expiry is reported to clients passing plain flags, too (RFC 6762 section 5.2)"
    # Same as expiry_no_goodbye, but browsing with the flags an external client would pass, i.e.
    # without SD_RESOLVED_NO_STALE. Record expiry must not be an implementation detail that only
    # resolved's own tooling gets to see.
    ref_expiry_scenario expiryplain RefExpiryPlain silent "$REF_BROWSE_FLAGS_PLAIN"
}

ref_scenario_query_backoff() {
    : "Repeated queries back off, each interval about twice the last (RFC 6762 section 5.2)"
    local out="$REF_TMPDIR/backoff.browse" listen_log="$REF_TMPDIR/backoff.listen"

    # Capture first, then browse: the interval doubles from one second, so the
    # first few repeats carry the whole answer and a short window suffices.
    ref_start_listener "$listen_log" 25 || return 2
    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_wait_listener || return 2

    # Three repeats give two gaps to compare, and every gap has to be clearly longer than the
    # one before it -- comparing only the first against the last would let an interior plateau
    # through. resolved doubles exactly, so 1.5 is pure tolerance for capture jitter, and the
    # factor-4 ceiling bounds the other side: an interval ballooning far past doubling would
    # silently kill discovery of later publishers and must not score as backoff.
    awk -v q="Q name=$REF_SERVICE.local qtype=12" '
        index($0, q) {
            if (prev != "") {
                gap = $1 - prev
                if (last != "" && (gap < last * 1.5 || gap > last * 4)) bad = 1
                last = gap
                gaps++
            }
            prev = $1
        }
        END {
            if (gaps < 2) exit 2
            exit bad ? 1 : 0
        }' "$listen_log"
    case "$?" in
        0) return 0 ;;
        1) cat "$listen_log" >&2; return 1 ;;
        *) cat "$listen_log" >&2; return 2 ;;
    esac
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
        grep -E "R qr=1 dst=$REF_IF1_PEER_ADDR_RE .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
            >/dev/null "$qu_log" && return 0

        # The QU question was asked and went unanswered by unicast: that is the verdict.
        cat "$qm_log" "$qu_log" >&2
        return 1
    done

    # Never got the multicast answer that makes unicast the conforming reply, so the scenario
    # never reached the behaviour it scores -- a harness error rather than a failed verdict.
    cat "$qm_log" >&2
    return 2
}

# Query the published service several times and echo the smallest
# question-to-answer delay in milliseconds. What is measured contains the two
# process wakeups around the answer, so the minimum of several samples keeps
# one descheduled reader from reading as a deliberate delay; a lost datagram
# costs a sample, not the run. Returns 2 when no sample got an answer.
ref_min_answer_delay() {
    local file_prefix="${1:?}"
    shift
    local q_log delay i min=""

    for i in 1 2 3; do
        q_log="$file_prefix.$i"
        ref_query "$q_log" "$REF_PUB_SERVICE.local" --duration 3 "$@" || return 2
        delay="$(awk -v ptr="ptr=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" \
            '/ QUERY name=/ { q = $1 }
             / R qr=1 / && index($0, ptr) && q != "" { printf "%d\n", ($1 - q) * 1000; exit }' "$q_log")"
        [[ -n "$delay" ]] || continue
        if [[ -z "$min" || "$delay" -lt "$min" ]]; then
            min="$delay"
        fi
    done

    [[ -n "$min" ]] || { cat "$file_prefix".* >&2; return 2; }
    echo "$min"
}

ref_scenario_shared_record_response_delay() {
    : "Responses to shared records are delayed 20-120ms (RFC 6762 section 6)"
    local min

    ref_ensure_pub_service || return 2

    # The PTR of a registered service is a shared record, so the response is
    # supposed to be spread over 20-120ms rather than sent immediately.
    min="$(ref_min_answer_delay "$REF_TMPDIR/delay.query")" || return 2
    [[ "$min" -ge 20 ]] || { echo >&2 "answered after ${min}ms at the fastest"; cat "$REF_TMPDIR/delay.query".* >&2; return 1; }
}

ref_scenario_responder_nsec() {
    : "A name that exists without the queried type is answered with NSEC (RFC 6762 section 6.1)"
    local q_log="$REF_TMPDIR/nsec.query"

    ref_ensure_pub_service || return 2

    # Control: the responder answers for this name at all (SRV, type 33).
    ref_query "$q_log.srv" "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --qtype 33 --duration 5 || return 2
    grep -E "R qr=1 .* name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=33" >/dev/null "$q_log.srv" ||
        { cat "$q_log.srv" >&2; return 2; }

    # The instance has SRV and TXT but no address record, so a query for one
    # should be answered with an NSEC (type 47) saying which types do exist.
    ref_query "$q_log" "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --qtype 1 --duration 5 || return 2
    grep -E "R qr=1 .* name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=47" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 1; }
}

ref_scenario_multiquestion_response_delay() {
    : "Answers to a multi-question query are delayed 20-120ms (RFC 6762 section 6.3)"
    local min

    ref_ensure_pub_service || return 2

    # Section 6.3: "for query messages containing more than one question, all
    # (non-defensive) answers SHOULD be randomly delayed in the range 20-120
    # ms", because the responder cannot know whether someone else is answering
    # the other questions. Nothing here is defending a name, so the exemption
    # for probe replies does not apply.
    min="$(ref_min_answer_delay "$REF_TMPDIR/mqdelay.query" \
        --witness-qname "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local")" || return 2
    [[ "$min" -ge 20 ]] || { echo >&2 "answered after ${min}ms at the fastest"; cat "$REF_TMPDIR/mqdelay.query".* >&2; return 1; }
}

ref_scenario_responder_aggregation() {
    : "Both questions of a two-question query are answered, in one packet (RFC 6762 sections 6.3 and 6.4)"
    local q_log="$REF_TMPDIR/aggregate.query"

    ref_ensure_pub_service || return 2

    # Two questions the responder owns an answer for: the shared type PTR and
    # the instance's own SRV. Section 6.3 requires answering "any or all of the
    # questions to which they have answers", section 6.4 asks for as few
    # packets as possible.
    ref_query "$q_log" "$REF_PUB_SERVICE.local" \
        --witness-qname "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --duration 5 || return 2

    # Both have to come back at all before their packing means anything.
    grep -E "R qr=1 .* name=$REF_PUB_SERVICE\.local type=12" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 2; }
    grep -E "R qr=1 .* name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=33" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 2; }

    ref_same_packet "$q_log" "name=$REF_PUB_SERVICE.local type=12" \
        "name=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local type=33" || { cat "$q_log" >&2; return 1; }
}

ref_scenario_responder_wildcard_query() {
    : "A qtype ANY query is answered with every matching record (RFC 6762 section 6.5)"
    local q_log="$REF_TMPDIR/wildcard.query"

    ref_ensure_pub_service || return 2

    # Section 6.5 departs from unicast DNS here: a responder "MUST respond with
    # *ALL* of its records that match the query", not merely one of them. The
    # instance owns an SRV and a TXT, so both have to come back.
    ref_query "$q_log" "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --qtype 255 --duration 5 || return 2

    # Pinned to sec=an: an SRV answered with the TXT riding along as an additional record does
    # not answer the ANY question, however routine that packing is for DNS-SD.
    grep -E "R qr=1 .* sec=an name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=33" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 1; }
    grep -E "R qr=1 .* sec=an name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=16" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 1; }

    # And in the same response, as answers.
    ref_same_packet "$q_log" "sec=an name=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local type=33" \
        "sec=an name=$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local type=16" || { cat "$q_log" >&2; return 1; }
}

ref_scenario_responder_legacy_unicast() {
    : "Legacy queries from an ephemeral port get unicast replies (RFC 6762 section 6.7)"
    local q_log="$REF_TMPDIR/legacy.query"

    ref_ensure_pub_service || return 2

    for _ in 1 2; do
        ref_query "$q_log" "$REF_PUB_SERVICE.local" --source-port 0 --duration 5 || return 2
        # The reply must be unicast to the querier's ephemeral port (a (wrong)
        # multicast-only reply would go to 224.0.0.251:5353 and never reach
        # this socket, showing up as an empty log), and must echo the query's
        # transaction ID (section 6.7) or a real legacy client could never
        # match it to its query.
        if grep -E "P qr=1 id=$REF_PEER_QUERY_ID dst=$REF_IF1_PEER_ADDR_RE" >/dev/null "$q_log" &&
           grep -E "R qr=1 dst=$REF_IF1_PEER_ADDR_RE sec=an name=$REF_PUB_SERVICE\.local type=12 ttl=[0-9]+ flush=0 ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" \
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

    ref_get_legacy_reply "$q_log" || return 2

    # Records in a legacy reply end up in an ordinary unicast DNS cache that
    # never sees the goodbyes or cache-flush updates keeping mDNS caches
    # coherent, hence section 6.7: the TTL "SHOULD NOT be greater than ten
    # seconds". A SHOULD, so this is tracked as a deviation, not a violation.
    grep -E "R qr=1 dst=$REF_IF1_PEER_ADDR_RE sec=an name=$REF_PUB_SERVICE\.local type=12 ttl=([0-9]|10) flush=" \
        >/dev/null "$q_log" || { cat "$q_log" >&2; return 1; }
}

ref_scenario_legacy_question_echo() {
    : "A legacy reply repeats the question it answers (RFC 6762 section 6.7)"
    local q_log="$REF_TMPDIR/legacyq.query"

    ref_ensure_pub_service || return 2

    ref_get_legacy_reply "$q_log" || return 2

    # Section 6.7 has the reply repeat the question, so that a resolver which
    # matches replies to queries by their question section can use it.
    grep -E "QE name=$REF_PUB_SERVICE\.local qtype=12" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 1; }
}

ref_scenario_querier_known_answers() {
    : "Continuous queries carry cached records as known answers (RFC 6762 section 7.1)"
    local out="$REF_TMPDIR/ka.browse" peer_log="$REF_TMPDIR/ka.peer" listen_log="$REF_TMPDIR/ka.listen"

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefKA || return 2
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

# Shared body of the known-answer suppression scenarios: send the witness-carrying query, require
# a fully decoded capture, and score the absence of a reply repeating our own answer. What varies
# is only how the known answer travels, so that stays at the call sites.
ref_known_answer_scenario() {
    local prefix="${1:?}"
    shift
    local q_log="$REF_TMPDIR/$prefix.query"

    ref_ensure_pub_service || return 2
    ref_query_with_witness "$q_log" "$@" || return 2
    ref_capture_fully_decoded "$q_log" || return 2

    if grep -E "R qr=1 dst=[^ ]+ .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" >/dev/null "$q_log"; then
        cat "$q_log" >&2
        return 1
    fi
}

ref_scenario_responder_known_answer_suppression() {
    : "Queries listing our answer with a fresh TTL must not be answered (RFC 6762 section 7.1)"
    # The known answer carries the full published TTL (120s), so section 7.1
    # permits suppression; any reply repeating it means suppression is not
    # implemented. The witness question rides in the same packet and is not
    # covered by that known answer, so its answer proves the packet arrived.
    ref_known_answer_scenario kasup
}

ref_scenario_known_answer_continuation() {
    : "Known answers in a follow-up packet suppress the reply (RFC 6762 section 7.2)"
    # TC set, known answer in a second packet: the responder is supposed to
    # defer 400-500ms, collect it, and then stay quiet. The witness question
    # travels in the first packet, so its answer proves that packet arrived --
    # and losing only the follow-up leaves the responder answering, which is
    # the tracked failure rather than a spurious pass.
    ref_known_answer_scenario kacont --tc --followup-known-answer
}

ref_scenario_conflict_rename() {
    : "A probe lost to a defending host is answered by picking a new name (RFC 6762 section 8.1)"
    local listen_log="$REF_TMPDIR/conflict.listen" peer_log="$REF_TMPDIR/conflict.peer"
    local conflict_file="$REF_CONFLICT_DNSSD_FILE"

    # The peer already owns the instance name resolved is about to claim, and
    # answers its probe. Section 8.1 has the prober defer to the existing host
    # and choose a new name, which manager_next_dnssd_names() does. This is
    # neither the section 8.2 tiebreak (that decides between hosts probing at
    # the same time) nor a section 9 conflict (that needs a record resolved is
    # already authoritative for; this one never left probing).
    #
    # Note the renaming only happens once dnssd_signal_conflict() has marked
    # the service withdrawn, and that returns early unless the bus is up.
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefConflict --service _refconf._udp || return 2
    sleep 2

    # shellcheck disable=SC2064
    trap "trap - RETURN; rm -f $conflict_file; systemctl reload systemd-resolved.service 2>/dev/null || :" RETURN

    ref_write_dnssd_file "$conflict_file" RefConflict _refconf._udp 100
    ref_start_listener "$listen_log" 20 || return 2
    systemctl reload systemd-resolved.service || return 2
    ref_wait_listener || return 2

    # Positive controls: resolved must have probed for the contested name...
    grep "Q name=RefConflict._refconf._udp.local .*probe=1" >/dev/null "$listen_log" ||
        { cat "$listen_log" "$peer_log" >&2; return 2; }
    # ...and the peer must have answered it. Unopposed, resolved wins the
    # probe and keeps the name, which would look exactly like the failure
    # this scenario tracks.
    grep "REPLY questions=.*RefConflict\._refconf\._udp\.local" >/dev/null "$peer_log" ||
        { cat "$listen_log" "$peer_log" >&2; return 2; }

    # Having lost, it must claim a different name -- an announcement of an SRV
    # under the same type whose owner is not the contested name.
    grep -E "R qr=1 dst=[^ ]+ sec=an name=[^ ]+\._refconf\._udp\.local type=33 ttl=[1-9]" "$listen_log" |
        grep -v "name=RefConflict\._refconf\._udp\.local" >/dev/null ||
        { cat "$listen_log" >&2; return 1; }
}

ref_scenario_publisher_probe_announce() {
    : "resolved probes before announcing, and announces twice (RFC 6762 sections 8.1 and 8.3)"
    local listen_log="$REF_TMPDIR/pubannounce.listen" file="$REF_PROBE_DNSSD_FILE"
    local announces instance probes rc=1

    # shellcheck disable=SC2064
    trap "trap - RETURN; rm -f $file; systemctl reload systemd-resolved.service 2>/dev/null || :" RETURN

    # A reload does not withdraw the records of a .dnssd file that went away
    # (that is the publisher_unregister_goodbye entry below), and dns_zone_put()
    # keeps an identical record rather than probing for it again, so
    # re-registering the same name would probe nothing. Claim a name the zone
    # has not seen instead, and a fresh one for each attempt.
    for _ in 1 2; do
        instance="RefProbe$RANDOM"
        ref_write_dnssd_file "$file" "$instance" "$REF_PUB_SERVICE" 8010
        ref_start_listener "$listen_log" 15 || return 2

        # Reload rather than restart: it re-runs the .dnssd loading logic while
        # leaving the runtime per-link mDNS switches intact.
        systemctl reload systemd-resolved.service || return 2
        ref_wait_listener || return 2

        # RFC 6762 section 8.1: the unique records must be probed for (a query
        # for the instance name carrying the proposed records in the authority
        # section), three times, 250ms apart -- the links are dedicated and
        # conflict-free, so all three probes must show up in the capture...
        probes="$({ grep -c "Q name=$instance.$REF_PUB_SERVICE.local .*probe=1" "$listen_log" || :; })"
        # ...and section 8.3: the service must be announced at least twice.
        # Type 33 is SRV; a positive TTL tells announcements from goodbyes.
        announces="$({ grep -cE "R qr=1 dst=[^ ]+ sec=an name=$instance.$REF_PUB_SERVICE.local type=33 ttl=[1-9]" "$listen_log" || :; })"
        if [[ "$probes" -ge 3 && "$announces" -ge 2 ]]; then
            rc=0
            break
        fi
    done

    [[ "$rc" -eq 0 ]] || cat "$listen_log" >&2
    return "$rc"
}

ref_scenario_goodbye_then_reannounce() {
    : "A service that says goodbye and comes back is reported again (RFC 6762 section 8.3)"
    local out="$REF_TMPDIR/rejoin.browse" peer_log="$REF_TMPDIR/rejoin.peer" before

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefRejoin --goodbye-on-exit || return 2
    ref_wait_event "$out" added RefRejoin "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 2; }

    kill "$REF_LAST_PEER_PID" || return 2
    ref_wait_event "$out" removed RefRejoin "$REF_IF1_INDEX" 30 || { cat "$out" "$peer_log" >&2; return 2; }

    # Same instance again: the browser has to report it a second time rather
    # than treat the name as still known. The event counts are cumulative over
    # the append-only browse output, so require growth past what is already
    # there rather than an absolute two -- a stray duplicate added event from
    # the first lifetime must not stand in for the re-announcement.
    before="$(ref_count_events "$out" added RefRejoin "$REF_IF1_INDEX")"
    ref_start_peer "$peer_log.2" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefRejoin || return 2
    ref_wait_event "$out" added RefRejoin "$REF_IF1_INDEX" 30 "$((before + 1))" && return 0

    cat "$out" "$peer_log.2" >&2
    return 1
}

ref_scenario_conflict_established() {
    : "A conflict on an established name returns it to probing (RFC 6762 section 9)"
    local listen_log="$REF_TMPDIR/estconf.listen" peer_log="$REF_TMPDIR/estconf.peer"
    local instance="RefEst" service="_refest._udp"

    # shellcheck disable=SC2064
    trap "trap - RETURN; rm -f $REF_EST_DNSSD_FILE; systemctl reload systemd-resolved.service 2>/dev/null || :" RETURN

    # Unlike the probe conflict above, section 9 is about a record the
    # responder is already authoritative for, so let it finish probing first.
    ref_write_dnssd_file "$REF_EST_DNSSD_FILE" "$instance" "$service" 8012
    systemctl reload systemd-resolved.service || return 2
    sleep 4

    ref_start_listener "$listen_log" 20 || return 2
    # The peer now claims the same name with different rdata.
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" "$instance" --service "$service" --port 41999 || return 2
    ref_wait_listener || return 2

    # Control: the conflicting claim reached the link.
    grep -E "R qr=1 .* name=$instance\.$service\.local type=33" >/dev/null "$listen_log" ||
        { cat "$listen_log" "$peer_log" >&2; return 2; }

    # Section 9 has the responder reset the conflicted record to probing
    # state, and recommends probing for a new name; either way a probe for a
    # name other than the contested one has to appear.
    grep -E "Q name=[^ ]+\.$service\.local .*probe=1" "$listen_log" |
        grep -v "name=$instance\.$service\.local" >/dev/null ||
        { cat "$listen_log" >&2; return 1; }
}

ref_scenario_goodbye() {
    : "A goodbye (TTL=0) announcement promptly yields a removed event (RFC 6762 section 10.1)"
    ref_expiry_scenario goodbye RefGoodbye goodbye "$REF_BROWSE_FLAGS"
}

ref_scenario_goodbye_single_announcement() {
    : "A goodbye is reported even for a service announced only once (RFC 6762 section 10.1)"
    # Section 10.1 ties the goodbye to the record the browser holds, not to how many times it was
    # announced, so one announcement has to be enough.
    ref_expiry_scenario gbonce RefGbOnce goodbye "$REF_BROWSE_FLAGS" --announce-count 1
}

ref_scenario_goodbye_shared_instance() {
    : "A goodbye from one of two publishers of the same instance leaves it available (RFC 6762 section 10.1)"
    # https://github.com/OpenPrinting/libcups/issues/81#issuecomment-5303811269
    local out="$REF_TMPDIR/sharedbye.browse" peer1_log="$REF_TMPDIR/sharedbye.peer1" peer2_log="$REF_TMPDIR/sharedbye.peer2"
    local second_addr="${REF_IF1_PEER_ADDR%.*}.3"
    local peer2_pid i

    # The second publisher has to be another machine on the SAME link: with a
    # distinct source address but the same interface, both copies of the
    # instance carry one (record, family, ifindex) identity at the browser.
    ip -n "$REF_NS" address add "$second_addr/24" dev "$REF_IF1_PEER" || return 2
    # shellcheck disable=SC2064
    trap "trap - RETURN; ip -n $REF_NS address del $second_addr/24 dev $REF_IF1_PEER 2>/dev/null || :" RETURN

    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer1_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefSharedBye || return 2
    ref_wait_event "$out" added RefSharedBye "$REF_IF1_INDEX" 30 ||
        { cat "$out" "$peer1_log" >&2; return 2; }

    # The trailing --hostname overrides the helper's per-interface default:
    # the second machine advertises its own host records, only the service
    # instance is shared.
    ref_start_peer "$peer2_log" "$REF_IF1_PEER" "$second_addr" RefSharedBye \
        --goodbye-on-exit --hostname refpeer-second.local || return 2
    peer2_pid="$REF_LAST_PEER_PID"
    # Both copies collapse onto the entry the browser already reported, so
    # there is no second added event to wait for; give the announcements a
    # moment instead, then have the second machine leave.
    sleep 3
    kill "$peer2_pid" || return 2

    # Control: both goodbyes really went out on the wire.
    for ((i = 0; i < 10; i++)); do
        grep "GOODBYE n=2" >/dev/null "$peer2_log" && break
        sleep 1
    done
    grep "GOODBYE n=2" >/dev/null "$peer2_log" || { cat "$peer2_log" >&2; return 2; }

    # Section 10.1's one-second goodbye grace exists precisely so that other
    # publishers of the same records can rescue them. The first machine keeps
    # answering the browse question all along, so the subscriber must not see
    # the instance disappear.
    sleep 8
    [[ "$(ref_count_events "$out" removed RefSharedBye "$REF_IF1_INDEX")" -eq 0 ]] ||
        { cat "$out" "$peer1_log" "$peer2_log" >&2; return 1; }
}

ref_scenario_publisher_unregister_goodbye() {
    : "Unregistering a service sends goodbyes for its records (RFC 6762 section 10.1)"
    local listen_log="$REF_TMPDIR/pubunreg.listen"

    ref_ensure_pub_service || return 2
    rm -f "$REF_PUB_DNSSD_FILE"
    ref_start_listener "$listen_log" 10 || return 2

    systemctl reload systemd-resolved.service || return 2
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

ref_scenario_cache_flush_update() {
    : "A re-announced unique record replaces the cached one (RFC 6762 section 10.2)"
    local peer_log="$REF_TMPDIR/flush.peer" out="$REF_TMPDIR/flush.json"

    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefFlush --service _refflush._udp --port 41001 || return 2
    sleep 4
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService \
        "{ \"name\": \"RefFlush\", \"type\": \"_refflush._udp\", \"domain\": \"local\", \"ifindex\": $REF_IF1_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 2; }
    grep '"port":41001' >/dev/null "$out" || { cat "$out" >&2; return 2; }

    # Same instance, new port, announced with the cache-flush bit set.
    kill -KILL "$REF_LAST_PEER_PID" || return 2
    ref_start_peer "$peer_log.2" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefFlush --service _refflush._udp --port 41002 || return 2
    sleep 4

    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService \
        "{ \"name\": \"RefFlush\", \"type\": \"_refflush._udp\", \"domain\": \"local\", \"ifindex\": $REF_IF1_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 2; }
    grep '"port":41002' >/dev/null "$out" || { cat "$out" "$peer_log.2" >&2; return 1; }
}

ref_scenario_case_insensitive_match() {
    : "Names must match case-insensitively (RFC 6762 section 16)"
    local out="$REF_TMPDIR/case.browse" peer_log="$REF_TMPDIR/case.peer"

    # Subscribe with the all-lowercase type; the peer announces mixed case.
    # The later --service wins over the one ref_start_peer passes.
    ref_start_browse "$out" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefCase --service _Ref._UDP || return 2

    ref_wait_added_name "$out" RefCase 30 || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_responder_authoritative_bit() {
    : "Responses set the authoritative answer bit (RFC 6762 section 18.4)"
    local q_log="$REF_TMPDIR/aabit.query"

    ref_ensure_pub_service || return 2
    ref_query "$q_log" "$REF_PUB_SERVICE.local" --duration 5 || return 2

    # Section 18.4: in responses for multicast domains the bit "MUST be set to
    # one", since leaving it clear would suggest better information exists
    # elsewhere.
    grep -E "P qr=1 .* aa=1 " >/dev/null "$q_log" || { cat "$q_log" >&2; return 1; }
}

ref_scenario_responder_rcode() {
    : "Responses carry rcode zero, and queries that do not are ignored (RFC 6762 section 18.11)"
    local q_log="$REF_TMPDIR/rcode.query" query_pid

    ref_ensure_pub_service || return 2

    # Section 18.11, first half: the response code "MUST be zero on
    # transmission" in both queries and responses.
    ref_query "$q_log.zero" "$REF_PUB_SERVICE.local" --duration 5 || return 2
    grep -E "P qr=1 .* rcode=0$" >/dev/null "$q_log.zero" || { cat "$q_log.zero" >&2; return 1; }

    # Second half: messages "received with non-zero Response Codes MUST be
    # silently ignored". A witness question cannot prove liveness here -- the
    # whole message must be ignored -- so a marker query loops back into this
    # same capture instead, pinning that the socket heard the group while
    # resolved stayed silent. The zero-rcode reply above lives in a different
    # capture on a different socket and says nothing about this one.
    ref_query "$q_log" "$REF_PUB_SERVICE.local" --rcode 3 --duration 5 &
    query_pid=$!
    sleep 1
    ref_query "$q_log.marker" "refmark._udp.local" --duration 1 || { wait "$query_pid" || :; return 2; }
    wait "$query_pid" || return 2
    ref_capture_fully_decoded "$q_log" || return 2
    grep "Q name=refmark._udp.local" >/dev/null "$q_log" || { cat "$q_log" >&2; return 2; }
    if grep -E "R qr=1 .* ptr=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local" >/dev/null "$q_log"; then
        cat "$q_log" >&2
        return 1
    fi
}

ref_scenario_responder_compressed_question() {
    : "A question named by a compression pointer is answered (RFC 6762 section 18.14)"
    local q_log="$REF_TMPDIR/compressed.query"

    ref_ensure_pub_service || return 2

    # Section 18.14 asks senders to compress successive questions that share a
    # name, and requires receivers to decode that: "Implementations receiving
    # Multicast DNS messages MUST correctly decode compressed names appearing
    # in the Question Section". Both questions here ask about the instance, so
    # the second points at the first rather than spelling the name out again --
    # the form mDNSResponder puts on the wire, and the one the Thread
    # conformance test for multi-question queries sends
    # (openthread/ot-br-posix#3446).
    ref_query "$q_log" "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --qtype 33 \
        --witness-qname "$REF_PUB_INSTANCE.$REF_PUB_SERVICE.local" --witness-qtype 16 \
        --compress-witness --duration 5 || return 2

    # The first question is spelled out, so an unanswered one means the query
    # never arrived rather than that the pointer went unread.
    grep -E "R qr=1 .* name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=33" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 2; }

    grep -E "R qr=1 .* name=$REF_PUB_INSTANCE\.$REF_PUB_SERVICE\.local type=16" >/dev/null "$q_log" ||
        { cat "$q_log" >&2; return 1; }
}

ref_scenario_resolve_service() {
    : "A discovered service resolves to host, port and TXT (RFC 6763 section 5)"
    local out="$REF_TMPDIR/resolve.json"

    # The containers publish these; browsing only reports that an instance
    # exists, resolving it is the other half of DNS-SD. The instance name, type and port come
    # assembled from the parent's exported fixture contract rather than being rebuilt here from
    # its pieces, so a reshaped .dnssd generation cannot silently turn into a bogus "regressed".
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveService \
        "{ \"name\": \"$FIXTURE_SERVICE_INSTANCE\", \"type\": \"$FIXTURE_SERVICE_TYPE\", \"domain\": \"local\", \"ifindex\": $BRIDGE_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 1; }

    grep -E "\"port\":${FIXTURE_SERVICE_PORT}[,}]" >/dev/null "$out" ||
        { cat "$out" >&2; return 1; }
    grep "\"hostname\":\"$CONTAINER_1.local\"" >/dev/null "$out" ||
        { cat "$out" >&2; return 1; }
    grep '"txt":\["DC=Device' >/dev/null "$out" || { cat "$out" >&2; return 1; }
}

ref_scenario_browse_subtype() {
    : "Browsing a service subtype yields its instances (RFC 6763 section 7.1)"
    local out="$REF_TMPDIR/subtype.browse" peer_log="$REF_TMPDIR/subtype.peer"

    ref_start_browse "$out" "$REF_IF1_INDEX" "" "_vendor._sub.$REF_SERVICE.local" || return 2
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefSub --subtype _vendor || return 2

    ref_wait_added_name "$out" RefSub 30 || { cat "$out" "$peer_log" >&2; return 1; }
}

ref_scenario_publisher_subtype() {
    : "A service published with a subtype is found by a subtype browse (RFC 6763 section 7.1)"
    local out="$REF_TMPDIR/pubsub.browse"

    systemd-run -M "$CONTAINER_1" --wait --pipe -- tee /etc/systemd/dnssd/subtype-canary.dnssd <<EOF || return 2
[Service]
Name=Subtype Canary on %H
Type=_testSubtype._udp
SubType=_vendor
Port=8011
TxtText=DC=Device
EOF
    # The canary is state in the parent-owned fixture container: arm the cleanup
    # right after writing it, so no early exit leaks it into later scenarios.
    # shellcheck disable=SC2064
    trap "trap - RETURN; systemd-run -M $CONTAINER_1 --wait --pipe -- rm -f /etc/systemd/dnssd/subtype-canary.dnssd 2>/dev/null || :; systemd-run -M $CONTAINER_1 --wait --pipe -- systemctl reload systemd-resolved.service 2>/dev/null || :" RETURN
    systemd-run -M "$CONTAINER_1" --wait --pipe -- systemctl reload systemd-resolved.service || return 2

    ref_start_browse "$out" "$BRIDGE_INDEX" "" "_vendor._sub._testSubtype._udp.local" || return 2
    ref_wait_added_name "$out" "Subtype Canary on $CONTAINER_1" 30 || { cat "$out" >&2; return 1; }
}

ref_scenario_responder_service_enumeration() {
    : "Service type enumeration lists registered types (RFC 6763 section 9)"
    local q_log="$REF_TMPDIR/enum.query"

    ref_ensure_pub_service || return 2

    # ref_ensure_pub_service above registers RefPub89 if nothing else has.
    # One retry, like any real querier would: a single datagram each way is not
    # a fair single point of failure on a loaded runner.
    for _ in 1 2; do
        ref_query "$q_log" "_services._dns-sd._udp.local" --duration 5 || return 2
        # flush=0: the enumeration PTR is a shared record -- every responder
        # on the link contributes its own types, so the cache-flush bit must
        # be clear on it (RFC 6762 section 10.2).
        grep -E "R qr=1 dst=[^ ]+ sec=an name=_services._dns-sd._udp.local type=12 ttl=[1-9][0-9]* flush=0 ptr=$REF_PUB_SERVICE\.local" \
            >/dev/null "$q_log" && return 0
    done

    cat "$q_log" >&2
    return 1
}

ref_scenario_duplicate_question_suppression() {
    : "A second browser for the same question adds no queries on the wire (commit 8458b7fb91ea)"
    # One question on the wire, no matter how many local subscribers. RFC 6762
    # section 7.3 asks this of a host that sees *another host* ask the same
    # question, not of one daemon serving two of its own clients, so the basis
    # here is systemd's own TODO rather than the RFC.
    local out_a="$REF_TMPDIR/dup.browse-a" out_b="$REF_TMPDIR/dup.browse-b"
    local peer_log="$REF_TMPDIR/dup.peer" listen_log="$REF_TMPDIR/dup.listen"
    local queries

    ref_start_browse "$out_a" "$REF_IF1_INDEX" || return 2
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefDup || return 2
    ref_wait_event "$out_a" added RefDup "$REF_IF1_INDEX" 30 || { cat "$out_a" "$peer_log" >&2; return 2; }

    # Let the first browser's re-query schedule back off (the intervals
    # double), so at most one of its queries can fall into the window below.
    sleep 10

    ref_start_listener "$listen_log" 15 || return 2
    ref_start_browse "$out_b" "$REF_IF1_INDEX" || return 2

    # Positive control: the second subscriber must get the service, too.
    ref_wait_event "$out_b" added RefDup "$REF_IF1_INDEX" 10 || { cat "$out_b" >&2; return 2; }

    # The canary proves the listener was capturing throughout the window the count below
    # scores on.
    ref_marker_canary "$REF_TMPDIR/dup.marker" "$listen_log" || return 2

    # More than one query in the window means the second subscriber spawned
    # its own query engine (a fresh engine starts at ~1s intervals).
    queries="$({ grep -c "Q name=$REF_SERVICE.local qtype=12" "$listen_log" || :; })"
    [[ "$queries" -le 1 ]] || { cat "$listen_log" >&2; return 1; }
}

ref_scenario_dual_stack_resolution() {
    : "A hostname query returns both address families, not just one (#25855)"
    local out="$REF_TMPDIR/dualstack.json" family

    # Controls: both families resolve when asked for by name, so anything
    # missing below is the combining of the two, not the publisher.
    for family in 2 10; do
        varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
            "{ \"name\": \"$CONTAINER_1.local\", \"family\": $family, \"ifindex\": $BRIDGE_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
            >"$out.$family" 2>&1 || { cat "$out.$family" >&2; return 2; }
        grep "\"family\":$family" >/dev/null "$out.$family" || { cat "$out.$family" >&2; return 2; }
    done

    # Asking for neither in particular has to yield both.
    varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname \
        "{ \"name\": \"$CONTAINER_1.local\", \"ifindex\": $BRIDGE_INDEX, \"flags\": $REF_BROWSE_FLAGS }" \
        >"$out" 2>&1 || { cat "$out" >&2; return 2; }

    grep '"family":2' >/dev/null "$out" || { cat "$out" >&2; return 1; }
    grep '"family":10' >/dev/null "$out" || { cat "$out" >&2; return 1; }
}

ref_scenario_multi_interface_ptr_query() {
    : "A query across all interfaces returns the services of every interface (#38380)"
    local peer1_log="$REF_TMPDIR/multi.peer1" peer2_log="$REF_TMPDIR/multi.peer2"
    local out="$REF_TMPDIR/multi.rr"

    ref_start_peer "$peer1_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefIf1 --service _refmulti._udp || return 2
    ref_start_peer "$peer2_log" "$REF_IF2_PEER" "$REF_IF2_PEER_ADDR" RefIf2 --service _refmulti._udp || return 2
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

ref_scenario_no_cache_lookup() {
    : "A lookup that bypasses the cache still finds what the cache holds (#40581)"
    local peer_log="$REF_TMPDIR/nocache.peer" out="$REF_TMPDIR/nocache.rr"
    local service="_refnocache._udp"

    # The publisher has to honour known answers for this to mean anything: the
    # reported failure is resolved listing the cached record as a known answer,
    # the responder staying silent because of it, and the cached copy then being
    # withheld from the caller. A responder that always answers hides all that.
    ref_start_peer "$peer_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefNoCache \
        --service "$service" --suppress-known-answers || return 2
    sleep 4

    # Control: the record is discoverable, and now cached.
    ref_resolve_ptr "$out.warm" "$service.local" "$REF_IF1_INDEX" || return 2
    grep RefNoCache >/dev/null "$out.warm" || { cat "$out.warm" "$peer_log" >&2; return 2; }

    # The same lookup asking not to use the cache must still answer from the
    # wire rather than come back empty. Coming back empty is what is being
    # scored, and resolved reports it as a failed call (MaxAttemptsReached)
    # rather than an empty answer, so both count as the same failure.
    if ! ref_resolve_ptr "$out.nocache" "$service.local" "$REF_IF1_INDEX" "$REF_BROWSE_FLAGS_NO_CACHE" ||
       ! grep RefNoCache >/dev/null "$out.nocache"; then
        cat "$out.nocache" "$peer_log" >&2
        return 1
    fi
}

ref_scenario_two_interfaces_same_name() {
    : "The same instance name announced on two links yields an added event per link (libcups#81)"
    # https://github.com/OpenPrinting/libcups/issues/81#issuecomment-5122506798
    local out="$REF_TMPDIR/twoif.browse" peer1_log="$REF_TMPDIR/twoif.peer1" peer2_log="$REF_TMPDIR/twoif.peer2"

    ref_start_browse "$out" 0 || return 2
    ref_start_peer "$peer1_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefTwoIf || return 2
    # Positive control, the tracked assertion is the second link below.
    ref_wait_event "$out" added RefTwoIf "$REF_IF1_INDEX" 30 || { cat "$out" "$peer1_log" >&2; return 2; }

    ref_start_peer "$peer2_log" "$REF_IF2_PEER" "$REF_IF2_PEER_ADDR" RefTwoIf || return 2
    if ! ref_wait_event "$out" added RefTwoIf "$REF_IF2_INDEX" 10; then
        # Distinguish the tracked conformance failure from a peer that died.
        kill -0 "$REF_LAST_PEER_PID" 2>/dev/null || { cat "$out" "$peer2_log" >&2; return 2; }
        cat "$out" "$peer2_log" >&2
        return 1
    fi
}

ref_scenario_goodbye_one_interface() {
    : "A goodbye on one link removes only that link's instance, the other lives on (libcups#81)"
    local out="$REF_TMPDIR/halfbye.browse" peer1_log="$REF_TMPDIR/halfbye.peer1" peer2_log="$REF_TMPDIR/halfbye.peer2"
    local peer2_pid

    ref_start_browse "$out" 0 || return 2
    ref_start_peer "$peer1_log" "$REF_IF1_PEER" "$REF_IF1_PEER_ADDR" RefHalfBye || return 2
    ref_wait_event "$out" added RefHalfBye "$REF_IF1_INDEX" 30 || { cat "$out" "$peer1_log" >&2; return 2; }

    ref_start_peer "$peer2_log" "$REF_IF2_PEER" "$REF_IF2_PEER_ADDR" RefHalfBye --goodbye-on-exit || return 2
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

run_conformance_scorecard() {
    : "Score resolved's mDNS/DNS-SD conformance scenario by scenario"

    # Each entry is a TODO: a conformance gap this test tracks rather than
    # gates on, tagged with the requirement level it misses -- MUST is a
    # violation, SHOULD a deviation -- so the table doubles as a work list.
    local -A known_failures=(
        # Without SD_RESOLVED_NO_STALE the per-service maintenance timer is
        # armed from a bogus cache expiry timestamp and dies after one shot, so
        # silently vanished publishers are never reported as removed.
        [expiry_no_goodbye_plain_flags]="TODO, SHOULD (RFC 6762 section 5.2): maintenance timer dies without SD_RESOLVED_NO_STALE"
        # Identical records from different machines share a single cache entry
        # owned by whichever announced last, so one machine's goodbye drops
        # the instance for the subscriber even while the other machine still
        # answers -- a spurious removed(+added) flap that can stand until the
        # continuous query comes around, up to an hour into a browse.
        # https://github.com/OpenPrinting/libcups/issues/81#issuecomment-5303811269
        [goodbye_shared_instance]="TODO, SHOULD (RFC 6762 section 10.1): one publisher's goodbye removes an instance other publishers still answer for"
        # Reloading drops deregistered .dnssd services from the registry
        # without withdrawing their records: no goodbyes are sent (and the
        # stale records even remain in the local zone).
        [publisher_unregister_goodbye]="TODO, SHOULD (RFC 6762 section 10.1): dnssd_registered_service_clear_on_reload() does not withdraw"
        # No goodbye packets are sent for published services on daemon stop.
        [publisher_stop_goodbye]="TODO, SHOULD (RFC 6762 section 10.1): no goodbyes on stop, see #30421"
        # Section 6.1 makes NSEC the answer for a type that does not exist at
        # a name the responder owns; resolved just stays silent.
        [responder_nsec]="TODO, MUST (RFC 6762 section 6.1): a missing type at an owned name is answered with silence, not NSEC"
        # dns_zone_item_conflict() withdraws the item rather than putting it
        # back into probing, so the name is simply given up.
        [conflict_established]="TODO, MUST (RFC 6762 section 9): a conflict withdraws the established record instead of returning it to probing"
        # dns_transaction_emit_udp() adds known answers whenever the key is
        # shared, whatever the flags say, while SD_RESOLVED_NO_CACHE stops the
        # cached copy being returned -- so against a responder that honours
        # section 7.1 the caller gets nothing at all. GH-23845 proposed a fix.
        [no_cache_lookup]="TODO (#40581): a NO_CACHE lookup comes back empty once the record is cached"
        # Reported in #20267: the query goes to the mDNS group even though the
        # name is in neither link-local reverse zone nor the link's subnet.
        [reverse_lookup_non_local]="TODO (#20267): a reverse lookup outside the link-local zones is also asked over mDNS"
        # Reported in #38380: only the services of one interface come back.
        [multi_interface_ptr_query]="TODO (#38380): a query on all interfaces returns only one interface's services"
        # Reported in #19003 and #25855: the answer carries one family only,
        # although each family resolves when asked for by name.
        [dual_stack_resolution]="TODO (#25855): a hostname query returns one address family, not both"
        [shared_record_response_delay]="TODO, SHOULD (RFC 6762 section 6): shared-record responses are sent immediately"
        # Section 6.3 asks for the same delay on every answer to a query that
        # carries more than one question, whatever the records are, since the
        # responder cannot know who else is answering the other questions.
        [multiquestion_response_delay]="TODO, SHOULD (RFC 6762 section 6.3): answers to a multi-question query are sent immediately"
        # Reported in #14119: the follow-up packet carries no question, so
        # mdns_scope_process_query() drops it and answers anyway.
        [known_answer_continuation]="TODO, MUST (RFC 6762 section 7.2): known answers in a follow-up packet are ignored, see #14119"
        # mdns_scope_process_query never looks at the query's answer section,
        # so it re-answers queries that already carry the answer.
        [responder_known_answer_suppression]="TODO, MUST (RFC 6762 section 7.1): responder-side suppression not implemented"
        # Replies to legacy queries are built from the zone with the records'
        # full TTLs; nothing implements the ten-second cap.
        [responder_legacy_ttl_cap]="TODO, SHOULD (RFC 6762 section 6.7): legacy reply TTLs are not capped to ten seconds"
        # Every BrowseServices subscriber runs its own query engine, so wire
        # traffic scales with the subscriber count (known since the browser
        # was introduced, see the TODO in commit 8458b7fb91ea).
        [duplicate_question_suppression]="TODO: one query engine per subscriber, see the TODO in commit 8458b7fb91ea"
    )
    # Ordered by the requirement each one checks: RFC 6762 by section, then
    # RFC 6763, then the ones whose only basis is a report. The scenarios do
    # not depend on each other or on this order.
    local scenarios=(
        announce                            # baseline
        hostname_resolution                 # 6762 section 3
        reverse_lookup                      # 6762 section 4
        reverse_lookup_non_local            # 6762 section 4
        expiry_no_goodbye                   # 6762 section 5.2
        expiry_no_goodbye_plain_flags       # 6762 section 5.2
        query_backoff                       # 6762 section 5.2
        responder_unicast_qu                # 6762 section 5.4
        shared_record_response_delay        # 6762 section 6
        responder_nsec                      # 6762 section 6.1
        multiquestion_response_delay        # 6762 section 6.3
        responder_aggregation               # 6762 sections 6.3 and 6.4
        responder_wildcard_query            # 6762 section 6.5
        responder_legacy_unicast            # 6762 section 6.7
        responder_legacy_ttl_cap            # 6762 section 6.7
        legacy_question_echo                # 6762 section 6.7
        querier_known_answers               # 6762 section 7.1
        responder_known_answer_suppression  # 6762 section 7.1
        known_answer_continuation           # 6762 section 7.2
        conflict_rename                     # 6762 section 8.1
        publisher_probe_announce            # 6762 sections 8.1 and 8.3
        goodbye_then_reannounce             # 6762 section 8.3
        conflict_established                # 6762 section 9
        goodbye                             # 6762 section 10.1
        goodbye_single_announcement         # 6762 section 10.1
        goodbye_shared_instance             # 6762 section 10.1
        publisher_unregister_goodbye        # 6762 section 10.1
        publisher_stop_goodbye              # 6762 section 10.1
        cache_flush_update                  # 6762 section 10.2
        case_insensitive_match              # 6762 section 16
        responder_authoritative_bit         # 6762 section 18.4
        responder_rcode                     # 6762 section 18.11
        responder_compressed_question       # 6762 section 18.14
        resolve_service                     # 6763 section 5
        browse_subtype                      # 6763 section 7.1
        publisher_subtype                   # 6763 section 7.1
        responder_service_enumeration       # 6763 section 9
        duplicate_question_suppression      # commit 8458b7fb91ea
        dual_stack_resolution               # #19003, #25855
        multi_interface_ptr_query           # #38380
        no_cache_lookup                     # #40581
        two_interfaces_same_name            # libcups#81
        goodbye_one_interface               # libcups#81
    )
    local -A results=()
    local peer_addrs=("$REF_IF1_PEER_ADDR" "$REF_IF2_PEER_ADDR")
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

    local ref_ifs=("$REF_IF1" "$REF_IF2")
    local ref_peer_ifs=("$REF_IF1_PEER" "$REF_IF2_PEER")
    for i in 1 2; do
        local host_if="${ref_ifs[i - 1]}" peer_if="${ref_peer_ifs[i - 1]}"
        ip link add "$host_if" type veth peer name "$peer_if" netns "$REF_NS"
        # Keep the expected event stream exact: IPv4 only.
        sysctl -qw "net.ipv6.conf.$host_if.disable_ipv6=1"
        ip netns exec "$REF_NS" sysctl -qw "net.ipv6.conf.$peer_if.disable_ipv6=1"
        ip link set "$host_if" up
        # Both ends of a link come from the one constant, so they cannot drift apart.
        ip address add "${peer_addrs[i - 1]%.*}.1/24" dev "$host_if"
        ip -n "$REF_NS" link set "$peer_if" up
        ip -n "$REF_NS" address add "${peer_addrs[i - 1]}/24" dev "$peer_if"
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
        ref_cleanup_scenario_state
        results[$scenario]=$rc
        : "+++ scorecard scenario $scenario END (rc=$rc) +++"
    done

    echo "=== mDNS/DNS-SD conformance scorecard ==="
    for scenario in "${scenarios[@]}"; do
        rc="${results[$scenario]}"
        printf '%-36s %s%s\n' "$scenario" \
            "$([[ "$rc" -eq 0 ]] && echo PASS || echo FAIL)" \
            "${known_failures[$scenario]:+ (known failure: ${known_failures[$scenario]})}"
    done

    # The known-failure table is a work list: an entry that no longer names a live scenario is
    # stale — renamed or removed without updating the table — and must not linger.
    local key
    for key in "${!known_failures[@]}"; do
        if [[ -z "${results[$key]:-}" ]]; then
            echo >&2 "known_failures entry '$key' does not name a scenario"
            return 1
        fi
    done

    # And the reverse direction: a ref_scenario_* function that is not listed in scenarios[]
    # never runs and never shows on the scorecard -- written, reviewed, and silently dead.
    local fn
    for fn in $(compgen -A function ref_scenario_); do
        if [[ " ${scenarios[*]} " != *" ${fn#ref_scenario_} "* ]]; then
            echo >&2 "Scenario function $fn is not listed in scenarios[]"
            return 1
        fi
    done

    # The two response-delay scenarios score a wall-clock minimum of three samples; on a loaded
    # runner all three can exceed the 20ms floor without resolved having changed, so a PASS
    # there is reported but must not fail the run -- following its advice would drop the entry
    # and disable the check for good on the next slow run.
    local -A timing_scenarios=([shared_record_response_delay]=1 [multiquestion_response_delay]=1)

    for scenario in "${scenarios[@]}"; do
        rc="${results[$scenario]}"
        if [[ "$rc" -eq 0 && -n "${known_failures[$scenario]:-}" ]]; then
            if [[ -n "${timing_scenarios[$scenario]:-}" ]]; then
                echo >&2 "Scenario $scenario passed this run (timing-derived; its known-failure entry stays)"
            else
                echo >&2 "Scenario $scenario now passes: remove it from known_failures so it cannot regress"
                verdict=1
            fi
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

# Deliberately outside run_testcases and its testcase_ namespace -- the name says so: a filter
# aimed at the parent's testcases must not turn this file into a silent no-op or empty the
# parent's own run. The scorecard stays selectable as a whole through
# TEST_MATCH_SUBTEST=conformance. The subshell keeps its set -e and traps to itself, as
# run_testcases would have.
( run_conformance_scorecard )
