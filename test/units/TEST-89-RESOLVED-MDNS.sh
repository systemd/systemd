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

# SD_RESOLVED_MDNS_IPV4|SD_RESOLVED_MDNS_IPV6|SD_RESOLVED_NO_ZONE|SD_RESOLVED_NO_STALE
# (src/shared/resolved-def.h): browse over mDNS only, do not answer from our own
# zone, and never serve a stale cache entry.
BROWSE_FLAGS=$(((1 << 3) | (1 << 4) | (1 << 13) | (1 << 24)))

# The io.systemd.Resolve.BrowseServices parameters blob, for a service type
# (given without its .local suffix) on one interface -- 0 for all of them. An
# explicit third argument overrides the default flags.
browse_params() {
    printf '{ "domain": "%s.local", "type": "", "ifindex": %s, "flags": %s }' \
        "${1:?}" "${2:?}" "${3:-$BROWSE_FLAGS}"
}

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

# Did any 'removed' event whose name matches $3 arrive in $1 after byte offset $2? The needle
# defaults to matching any name, for the callers that mean "any removal at all".
removed_since() {
    local file="${1:?}" off="${2:?}" needle="${3:-.}"

    tail -c "+$((off + 1))" "$file" | { grep -oE '"updateFlag":"removed"[^}]*"name":"[^"]*"' || :; } | grep -e "$needle" >/dev/null
}

# Did $1 carry events for both address families? AF_INET is 2 and AF_INET6 is 10; every event
# carries the family it was discovered over, so this catches a snapshot missing one of them --
# which a bare event count cannot, both families being the same instances twice over.
both_families() {
    local file="${1:?}"

    grep '"family":2[,}]' "$file" >/dev/null && grep '"family":10[,}]' "$file" >/dev/null
}

# How many 'added' events has $1 seen? The counterpart of removed_since() for the other half of the
# event vocabulary.
added_count() {
    { grep -o '"updateFlag":"added"' "${1:?}" || :; } | wc -l
}

# Bring up a service-less dummy link with mDNS on, so a second (empty) mDNS scope exists for the
# ifindex=0 reconciliation to combine. The caller arms its own EXIT trap first -- the units and
# files to clean up differ per testcase, and the trap's link removal is harmless before the link
# exists. A previously interrupted run may have leaked the fixed-name link: RETURN traps do not fire
# when set -e aborts a function mid-flight, so clear it first to keep re-runs self-healing rather
# than tripping over EEXIST.
mdns_dummy_link_up() {
    local dummy="${1:?}" addr="${2:?}"

    ip link del "$dummy" 2>/dev/null || :
    ip link add "$dummy" type dummy
    ip link set "$dummy" up multicast on
    ip address add "$addr" dev "$dummy"
    resolvectl mdns "$dummy" yes
    [[ "$(resolvectl mdns "$dummy")" =~ :\ yes$ ]]
    sleep 2  # let resolved create the scope before we start browsing
}

# resolvectl only reads back the *configured* mDNS support; whether resolved actually built a scope
# for the link additionally depends on link_relevant() (carrier, multicast, operational state). A
# testcase that turns a scope off to observe the teardown asserts nothing if the scope never
# existed, so require resolved's own trace of having created it. Needs debug logging.
assert_mdns_scope_exists() {
    local dummy="${1:?}" since="${2:?}"
    local i

    for ((i = 0; i < 15; i++)); do
        if { journalctl -u systemd-resolved.service --since "$since" || :; } |
               grep "New scope on link $dummy, protocol mdns" >/dev/null; then
            return 0
        fi
        sleep 1
    done

    echo >&2 "resolved never created an mDNS scope for $dummy; the teardown below would assert nothing"
    journalctl -u systemd-resolved.service --since "$since" >&2 || :
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
    parameters="$(browse_params "$service_type" "${BRIDGE_INDEX:?}")"

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
    parameters="$(browse_params "$service_type" "$ifindex")"

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

    local out_file unit_name service_type added removed since orig_level
    local dummy="ravc-noflap"

    out_file="$(mktemp)"
    unit_name="varlinkctl-noflap-$SRANDOM.service"
    service_type="_testService5._udp"
    orig_level="$(resolvectl log-level)"
    since="$(date '+%Y-%m-%d %H:%M:%S')"

    # The flap only manifests when the browser reconciles >=2 same-family mDNS
    # scopes: the pre-fix code diffed the browser's global service list against
    # each scope's partial answer, spuriously removing services absent from that
    # one scope. The host normally has only the container bridge as an mDNS
    # interface, so add a service-less dummy link with mDNS enabled to guarantee a
    # second (empty) scope that the ifindex=0 reconciliation must combine. This
    # must succeed -- without the second scope the testcase asserts nothing, which is what
    # assert_mdns_scope_exists() below establishes rather than assuming.
    # Arm the cleanup before anything else can fail, so neither the fixed-name
    # link nor the output file leaks into later testcases: run_testcases runs
    # each testcase in its own subshell, whose EXIT trap fires however the
    # testcase ends. The browse unit may not exist yet, hence the best-effort
    # stop.
    # shellcheck disable=SC2064
    trap "resolvectl log-level $orig_level || :; systemctl stop $unit_name 2>/dev/null || :; ip link del $dummy 2>/dev/null || :; rm -f $out_file" EXIT

    resolvectl log-level debug
    mdns_dummy_link_up "$dummy" 169.254.171.171/16
    assert_mdns_scope_exists "$dummy" "$since"

    # Long-running browse across *all* interfaces (ifindex=0). With the
    # combined-answer reconciliation there must be no 'removed' event as long as
    # every publisher stays up. Use --timeout=infinity: the subscription goes idle
    # once everything is discovered, and varlinkctl's default 45s idle timeout
    # would sever it (and the assertion) mid-observation.
    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "$(browse_params "$service_type" "0")"

    # Wait until both containers' services (20 each, 40 total) have been
    # discovered. Count occurrences, not lines: varlinkctl --more emits compact
    # JSON-SEQ and one notify batches many entries onto a single line.
    for _ in {0..14}; do
        added="$(added_count "$out_file")"
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

testcase_browse_shared_querier() {
    : "Concurrent subscribers of one service type share a querier and each receives updates"
    resolvectl flush-caches

    local out1 out2 out3 unit1 unit2 unit3 service_type params params3 n1 n2 n3 since joins orig_level ok
    service_type="_testService8._udp"
    params="$(browse_params "$service_type" "${BRIDGE_INDEX:?}")"
    # The late joiner asks the same question with different flags -- but only in bits that cannot
    # change what an mDNS browse sees: DNS|LLMNR_IPV4|LLMNR_IPV6|NO_CNAME on top of the usual
    # MDNS_IPV4|MDNS_IPV6|NO_ZONE|NO_STALE. The subscribe path masks the
    # identity down to the bits that matter, so this must JOIN the shared querier; before that
    # mask, inert flag noise forked a second querier with its own wire schedule, ladder and
    # rescue budget.
    params3="$(browse_params "$service_type" "${BRIDGE_INDEX:?}" \
        "$((BROWSE_FLAGS | (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5)))")"
    out1="$(mktemp)"
    out2="$(mktemp)"
    out3="$(mktemp)"
    unit1="varlinkctl-shared1-$SRANDOM.service"
    unit2="varlinkctl-shared2-$SRANDOM.service"
    unit3="varlinkctl-shared3-$SRANDOM.service"

    # An EXIT trap, not RETURN: set -e aborts skip RETURN traps, and this subshell's EXIT trap
    # fires however the testcase ends — the infinity browse units must never outlive it. Armed
    # before anything can fail, so an early abort cleans up the files too. The level is captured
    # before it is raised below: the integration image boots with systemd.log_level=debug, and
    # restoring a hardcoded 'info' would quietly downgrade every testcase that follows.
    orig_level="$(resolvectl log-level)"
    # shellcheck disable=SC2064
    trap "systemctl stop $unit1 $unit2 $unit3 2>/dev/null || :; resolvectl log-level $orig_level || :; rm -f $out1 $out2 $out3" EXIT

    # Debug logging, so the sharing itself is observable below and not just its symptoms: every
    # assertion on the event streams alone is equally satisfied by one querier per subscriber.
    resolvectl log-level debug
    since="$(date '+%Y-%m-%d %H:%M:%S')"

    # Two concurrent subscriptions to the same question from the start. --timeout=infinity: both
    # must survive the ~120s TTL expiry phase below despite going idle in between.
    systemd-run --unit="$unit1" --service-type=exec -p StandardOutput="file:$out1" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$params"
    systemd-run --unit="$unit2" --service-type=exec -p StandardOutput="file:$out2" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$params"

    # Both subscribers must see all 40 services (20 per container; count 'added' occurrences like
    # the other testcases). The raw >=40 count alone could be satisfied by a single container's 20
    # services on two families, so also require that BOTH containers appear in each stream -- the
    # expiry phase below yanks CONTAINER_2 and would be doomed from the start if it was never
    # discovered -- and that BOTH address families do, since 20 instances per container on one
    # family alone would clear the count with the other family's half of the snapshot missing.
    local both=0
    for _ in {0..14}; do
        n1="$(added_count "$out1")"
        n2="$(added_count "$out2")"
        if [[ "$n1" -ge 40 && "$n2" -ge 40 ]] &&
           grep "on $CONTAINER_1" "$out1" >/dev/null && grep "on $CONTAINER_2" "$out1" >/dev/null &&
           grep "on $CONTAINER_1" "$out2" >/dev/null && grep "on $CONTAINER_2" "$out2" >/dev/null &&
           both_families "$out1" && both_families "$out2"; then
            both=1
            break
        fi
        sleep 2
    done
    if [[ "$both" -ne 1 ]]; then
        echo >&2 "Concurrent subscribers did not both discover both containers' services (n1=${n1:-0} n2=${n2:-0})"
        cat "$out1" "$out2" >&2
        return 1
    fi

    # The point of the whole testcase: those two subscriptions must be sharing one querier, which
    # only resolved itself can tell us. The second subscription logs that it joined the first's
    # querier; a regression that allocated a querier per subscriber would still satisfy every
    # assertion above and below, but would log nothing here.
    joins=0
    for _ in {0..9}; do
        joins="$( { journalctl -u systemd-resolved.service --since "$since" || :; } \
                  | { grep -c "Joining existing browse querier for $service_type" || :; })"
        [[ "$joins" -ge 1 ]] && break
        sleep 1
    done
    if [[ "$joins" -lt 1 ]]; then
        echo >&2 "The second subscriber did not join the first one's querier"
        journalctl -u systemd-resolved.service --since "$since" >&2 || :
        return 1
    fi

    # A late joiner of the same question is served a snapshot of the querier state and must not
    # need to wait for any wire traffic -- poll briefly only to absorb event-loop scheduling.
    systemd-run --unit="$unit3" --service-type=exec -p StandardOutput="file:$out3" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$params3"
    local snap=0
    for _ in {0..9}; do
        n3="$(added_count "$out3")"
        if [[ "$n3" -ge 40 ]] &&
           grep "on $CONTAINER_1" "$out3" >/dev/null && grep "on $CONTAINER_2" "$out3" >/dev/null &&
           both_families "$out3"; then
            snap=1
            break
        fi
        sleep 1
    done
    if [[ "$snap" -ne 1 ]]; then
        echo >&2 "Late joiner did not receive the full initial snapshot (n3=${n3:-0})"
        cat "$out3" >&2
        return 1
    fi

    # And it must have JOINED, not forked: its flags differ from the first two subscriptions'
    # only in bits inert for an mDNS browse, so the identity mask has to land it on the same
    # querier -- a second 'joining' line. Without the mask this held for identical flags only,
    # and the snapshot above would have been served just as happily by a fresh querier's first
    # cache-served query.
    joins=0
    for _ in {0..9}; do
        joins="$( { journalctl -u systemd-resolved.service --since "$since" || :; } \
                  | { grep -c "Joining existing browse querier for $service_type" || :; })"
        [[ "$joins" -ge 2 ]] && break
        sleep 1
    done
    if [[ "$joins" -lt 2 ]]; then
        echo >&2 "The inert-flag late joiner forked its own querier instead of joining (joins=$joins)"
        journalctl -u systemd-resolved.service --since "$since" >&2 || :
        return 1
    fi

    # Detaching one subscriber must not affect the others: checkpoint the survivors' streams
    # BEFORE the stop, hold a quiet window spanning several continuous-query revisits (as the
    # no-flap testcase does), and assert no 'removed' reached them. All publishers are still up,
    # so any hit here is detach-induced flap -- which would otherwise be indistinguishable from
    # the expiry-driven removals asserted below.
    local off1 off3
    off1="$(wc -c <"$out1")"
    off3="$(wc -c <"$out3")"

    systemctl stop "$unit2"
    sleep 12

    if tail -c "+$((off1 + 1))" "$out1" | grep '"updateFlag":"removed"' >/dev/null; then
        echo >&2 "Detaching a subscriber caused spurious 'removed' events for a surviving subscriber:"
        tail -c "+$((off1 + 1))" "$out1" >&2
        return 1
    fi
    if tail -c "+$((off3 + 1))" "$out3" | grep '"updateFlag":"removed"' >/dev/null; then
        echo >&2 "Detaching a subscriber caused spurious 'removed' events for the late joiner:"
        tail -c "+$((off3 + 1))" "$out3" >&2
        return 1
    fi

    # Take the second container off the network abruptly. The assertion here is the fan-out:
    # however the expired records get pruned (for a type the surviving publisher still answers,
    # its refreshes can drive the pruning just as well as the querier's TTL-maintenance ladder
    # -- testcase_mdns_remove_on_expiry is what pins down the ladder mechanism), every remaining
    # subscriber must receive the resulting 'removed' events, late joiner included.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl down host0

    local removed1=0 removed3=0
    for _ in {0..99}; do
        if [[ "$removed1" -eq 0 ]] && removed_since "${out1}" "${off1}" "on $CONTAINER_2"; then
            removed1=1
        fi
        if [[ "$removed3" -eq 0 ]] && removed_since "${out3}" "${off3}" "on $CONTAINER_2"; then
            removed3=1
        fi
        [[ "$removed1" -eq 1 && "$removed3" -eq 1 ]] && break
        sleep 2
    done

    if [[ "$removed1" -ne 1 || "$removed3" -ne 1 ]]; then
        echo >&2 "Expiry removals were not fanned out to all subscribers (removed1=$removed1 removed3=$removed3)"
        cat "$out1" "$out3" >&2
        systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl up host0 || :
        return 1
    fi

    # Restore the second container for the remaining testcases, and insist on it: run_testcases()
    # runs testcase_browse_unrelated_scope_teardown straight after this one, and that testcase
    # requires all 40 services inside a 30s gate with no reachability precondition of its own. A
    # restore that quietly failed here would surface there instead, reported against the
    # scope-teardown logic. Retried rather than one-shot, so a loaded runner missing wait-online's
    # cap once does not fail a testcase that has already asserted everything it set out to.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl up host0
    ok=0
    for _ in {0..2}; do
        if systemd-run -M "$CONTAINER_2" --wait --pipe -- \
               /usr/lib/systemd/systemd-networkd-wait-online --ipv4 --ipv6 --interface=host0 --operational-state=degraded --timeout=30; then
            ok=1
            break
        fi
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Could not restore $CONTAINER_2's network; later testcases would fail against it"
        return 1
    fi

    echo testcase_end
}

testcase_browse_unrelated_scope_teardown() {
    : "Losing one link's mDNS scope must not withdraw services discovered on another link"
    resolvectl flush-caches

    local out0 outb err0 errb unit0 unitb service_type off0 offb params0 paramsb since orig_level
    local dummy="ravc-scoped"

    out0="$(mktemp)"
    outb="$(mktemp)"
    err0="$(mktemp)"
    errb="$(mktemp)"
    unit0="varlinkctl-scoped0-$SRANDOM.service"
    unitb="varlinkctl-scopedb-$SRANDOM.service"
    service_type="_testService9._udp"
    params0="$(browse_params "$service_type" "0")"
    paramsb="$(browse_params "$service_type" "${BRIDGE_INDEX:?}")"
    orig_level="$(resolvectl log-level)"
    since="$(date '+%Y-%m-%d %H:%M:%S')"

    # A second mDNS link whose scope is torn down mid-subscription; the services under test live on
    # the bridge, never here. A previous interrupted run may have leaked the fixed-name link.
    # shellcheck disable=SC2064
    trap "resolvectl log-level $orig_level || :; systemctl stop $unit0 $unitb 2>/dev/null || :; ip link del $dummy 2>/dev/null || :; rm -f $out0 $outb $err0 $errb" EXIT

    resolvectl log-level debug
    mdns_dummy_link_up "$dummy" 169.254.172.172/16
    assert_mdns_scope_exists "$dummy" "$since"

    # Two live subscriptions: one across all interfaces, one pinned to the bridge. The purge that
    # the teardown below triggers is scoped to the vanishing link, so the pinned one is skipped
    # outright while the ifindex=0 one reconciles against the scopes that remain.
    systemd-run --unit="$unit0" --service-type=exec -p StandardOutput="file:$out0" -p StandardError="file:$err0" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$params0"
    systemd-run --unit="$unitb" --service-type=exec -p StandardOutput="file:$outb" -p StandardError="file:$errb" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices "$paramsb"

    local ready=0 n0 nb
    for _ in {0..14}; do
        n0="$(added_count "$out0")"
        nb="$(added_count "$outb")"
        if [[ "$n0" -ge 40 && "$nb" -ge 40 ]]; then
            ready=1
            break
        fi
        sleep 2
    done
    if [[ "$ready" -ne 1 ]]; then
        echo >&2 "Both subscribers did not discover the services (n0=${n0:-0} nb=${nb:-0})"
        cat "$out0" "$outb" >&2
        return 1
    fi

    # Checkpoint, then take the unrelated link's mDNS scope away.
    off0="$(wc -c <"$out0")"
    offb="$(wc -c <"$outb")"
    resolvectl mdns "$dummy" no
    [[ "$(resolvectl mdns "$dummy")" =~ :\ no$ ]]

    # The scope teardown purges the browse subscriptions. Give it the same settling window the
    # other no-flap negatives use, and anchor on a positive fact first: the services still resolve.
    sleep 2
    local ok=0
    for _ in {0..14}; do
        if resolvectl service "Test Service 180 on $CONTAINER_1" "$service_type" local >/dev/null; then
            ok=1
            break
        fi
        sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Services stopped resolving after an unrelated link's mDNS scope went away"
        return 1
    fi

    # That anchor reads this host's cache, which the browse path does not touch, so on its own it
    # would still hold with both subscriptions dead -- and a subscription the purge errored out and
    # unregistered emits no 'removed' either, which is exactly what the negative below checks for.
    # So pin the subscriptions themselves as live: publish a fresh instance of the browsed type and
    # require both streams to report it. An unsolicited announcement reaches a subscriber without
    # the querier's own schedule, so this pins liveness, not the schedule.
    systemd-run -M "$CONTAINER_1" --wait --pipe -- tee /etc/systemd/dnssd/scopedalive.dnssd <<EOF
[Service]
Name=Scope Teardown Liveness Canary
Type=$service_type
Port=8010
TxtText=DC=Device PN=123456 SN=1234567890
EOF
    systemd-run -M "$CONTAINER_1" --wait --pipe -- systemctl reload systemd-resolved.service

    local alive=0
    for _ in {0..14}; do
        if grep "Scope Teardown Liveness Canary" "$out0" >/dev/null &&
           grep "Scope Teardown Liveness Canary" "$outb" >/dev/null; then
            alive=1
            break
        fi
        sleep 2
    done
    systemd-run -M "$CONTAINER_1" --wait --pipe -- rm -f /etc/systemd/dnssd/scopedalive.dnssd || :
    systemd-run -M "$CONTAINER_1" --wait --pipe -- systemctl reload systemd-resolved.service || :
    if [[ "$alive" -ne 1 ]]; then
        echo >&2 "A browse subscription did not survive the unrelated scope teardown:"
        cat "$out0" "$err0" "$outb" "$errb" >&2
        return 1
    fi

    # The negative this testcase is named for. Note it is a weak discriminator on its own: the
    # combined-vs-per-scope reconcile it guards is already pinned by
    # testcase_browse_ifindex_zero_no_flap, and dropping the purge altogether emits nothing here
    # either. What it adds over that one is the teardown path specifically, now that the liveness
    # check above rules out the silent way to satisfy it.
    if removed_since "$out0" "$off0" || removed_since "$outb" "$offb"; then
        echo >&2 "Tearing down an unrelated link's mDNS scope withdrew services from the browse:"
        tail -c "+$((off0 + 1))" "$out0" >&2
        tail -c "+$((offb + 1))" "$outb" >&2
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

testcase_mdns_remove_on_expiry() {
    : "A service that vanishes without a goodbye must be removed when its records expire"

    local out_file error_file unit_name service_type
    out_file="$(mktemp)"
    error_file="$(mktemp)"
    unit_name="varlinkctl-expiry-$SRANDOM.service"
    service_type="_testExpiry._udp"

    # An EXIT trap, not RETURN: set -e aborts skip RETURN traps, and this subshell's EXIT trap
    # fires however the testcase ends — the infinity browse unit must never outlive it. Armed
    # before anything can fail, so an early abort cleans up the files too.
    # shellcheck disable=SC2064
    trap "systemctl stop $unit_name 2>/dev/null || :; rm -f $out_file $error_file" EXIT

    # Publish a canary service type from the second container ONLY. A type that
    # both containers publish cannot discriminate a broken maintenance ladder:
    # the surviving publisher keeps answering the browser's continuous PTR
    # query, and each successful completion of that query also revisits the
    # cache -- pruning expired records and emitting the very 'removed' event
    # this test is about, ladder or no ladder. With no surviving publisher, no
    # transaction completes successfully once the container is gone, so the
    # removal below is reachable only through the ladder's terminal fire.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- tee /etc/systemd/dnssd/expiry-canary.dnssd <<EOF
[Service]
Name=Expiry Canary on %H
Type=$service_type
Port=8010
TxtText=DC=Device PN=123456 SN=1234567890
EOF
    # Reload rather than restart: it re-runs dnssd_load() to pick up the new
    # file while leaving the runtime per-link mDNS switches from setup intact.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl reload systemd-resolved.service

    resolvectl flush-caches

    # Note: --timeout=infinity, because this subscription must outlive the 120s record
    # TTL: varlinkctl's default 45s method-call timeout would sever the connection --
    # and with it the server-side browser and its maintenance ladder -- long before
    # the expiry-driven removal that this test is about could be observed.
    systemd-run --unit="$unit_name" --service-type=exec -p StandardOutput="file:$out_file" -p StandardError="file:$error_file" \
        varlinkctl call --more --timeout=infinity /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.BrowseServices \
        "$(browse_params "$service_type" "${BRIDGE_INDEX:?}")"

    # Wait until the canary has been discovered.
    local ok=0
    for _ in {0..14}; do
        if grep "on $CONTAINER_2" >/dev/null "$out_file"; then
            ok=1
            break
        fi
        sleep 2
    done
    if [[ "$ok" -ne 1 ]]; then
        echo >&2 "Never discovered the expiry canary on $CONTAINER_2"
        cat "$out_file" "$error_file" >&2
        return 1
    fi

    # Checkpoint the output: only 'removed' events produced AFTER the container
    # goes away count, so a match is provably expiry-driven rather than some
    # earlier transient churn.
    local off
    off="$(wc -c <"$out_file")"

    # Yank the second container off the network *abruptly* (no goodbye). We do
    # NOT flush caches here: with the canary's only publisher gone, removal must
    # be driven purely by the browser's TTL-maintenance ladder re-confirming
    # and then, at TTL expiry, pruning the now-unanswered records and emitting
    # 'removed'.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl down host0

    # Records use MDNS_DEFAULT_TTL (120s); the terminal fire lands at ~down+120s
    # plus ladder jitter and event-loop slop, so poll generously (~200s).
    local removed=0
    for _ in {0..99}; do
        if removed_since "${out_file}" "${off}" "on $CONTAINER_2"; then
            removed=1
            break
        fi
        sleep 2
    done

    if [[ "$removed" -ne 1 ]]; then
        echo >&2 "$CONTAINER_2 services were not removed after their records expired"
        cat "$out_file" "$error_file" >&2
        systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl up host0 || :
        return 1
    fi

    # Restore the second container for the remaining testcases and withdraw the
    # canary again. Best-effort: the removal this testcase is about has already
    # been asserted above, and the next testcase re-downs host0 and brings it
    # back up with its own wait -- a transient hiccup here (say, wait-online
    # hitting its cap on a loaded runner) must not fail a passed testcase.
    systemd-run -M "$CONTAINER_2" --wait --pipe -- networkctl up host0 || :
    systemd-run -M "$CONTAINER_2" --wait --pipe -- \
        /usr/lib/systemd/systemd-networkd-wait-online --ipv4 --ipv6 --interface=host0 --operational-state=degraded --timeout=30 || :
    systemd-run -M "$CONTAINER_2" --wait --pipe -- rm /etc/systemd/dnssd/expiry-canary.dnssd || :
    systemd-run -M "$CONTAINER_2" --wait --pipe -- systemctl reload systemd-resolved.service || :

    echo testcase_end
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
