#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that stale alias state doesn't overwrite canonical unit state.
# 1. Legit unit is running (PID A).
# 2. Sus units are running (PID B, C, D...).
# 3. We alias sus -> legit.
# 4. If the bug triggers, legit unit's state is overwritten by a sus unit's state.
# 5. Legit unit thinks it is now PID B (or C, or D...).
# 6. We detect this PID change as proof of corruption.

declare -a abandoned_pids=()

reap_abandoned_pids() {
    local pid attempt

    if (( ${#abandoned_pids[@]} == 0 )); then
        return 0
    fi

    echo "Reaping ${#abandoned_pids[@]} abandoned processes..."

    for pid in "${abandoned_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    for pid in "${abandoned_pids[@]}"; do
        for attempt in $(seq 1 50); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi

            sleep 0.1
        done

        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi

        for attempt in $(seq 1 50); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi

            sleep 0.1
        done

        if kill -0 "$pid" 2>/dev/null; then
            echo "ERROR: Failed to reap abandoned process PID $pid"
            return 1
        fi
    done

    abandoned_pids=()
}

# Wait until at least one job for a unit name matching the given prefix is
# queued. Used to make sure the serialized state we're about to dump contains
# embedded 'job\n...\n\n' subsections so the deserialization path is fully
# exercised.
wait_for_pending_job() {
    local prefix="${1:?}"
    local i unit

    for i in {1..100}; do
        for unit in $(systemctl list-jobs --no-legend | awk '{print $2}'); do
            if [[ "$unit" == "$prefix"* ]]; then
                return 0
            fi
        done
        sleep 0.1
    done

    echo "ERROR: no $prefix* jobs are pending"
    systemctl list-jobs || true
    return 1
}

run_test() {
    local reload_cmd="${1:?}"
    # If "with_pending_jobs", also queue hanging reload jobs on the running sus
    # units, so that the serialized state contains embedded 'job' subsections
    # to fully exercise the deserialization
    local pending_jobs="${2:-}"
    local n_sus=20
    local current_pid journal_warnings new_pid orig_pid p pid reload_start orphan orphan_cgroup unit warning_count
    local orphan_units

    if [[ "$pending_jobs" == "with_pending_jobs" ]]; then
        n_sus=100
    fi

    echo ""
    echo "========================================="
    echo "Testing with: systemctl $reload_cmd${pending_jobs:+ ($pending_jobs)}"
    echo "========================================="

    cat >/run/systemd/system/legit.service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF

    # Create 100 sus units. They must be running so systemd CANNOT garbage
    # collect them. If they are dead/stopped, systemd can remove them from
    # memory before serialization.
    #
    # In with_pending_jobs mode they additionally get a pending reload job
    # queued via 'systemctl --no-block reload' AFTER they are running, so the
    # serialized stream contains 'job\n...\n\n' subsections AND the units have
    # a real MainPID. The skip-desync regression in unit_deserialize_state_skip()
    # stops at the job subsection's empty line marker, leaving the rest of the
    # serialized stream to be consumed as garbage. If legit.service is dropped
    # from the collected names set as a result, the alias-protection branch in
    # manager_deserialize_one_unit() is bypassed and a sus unit's MainPID
    # overwrites legit.service's MainPID.
    echo "Creating $n_sus sus units..."
    for i in $(seq -f "%03g" 1 "$n_sus"); do
        cat >/run/systemd/system/sus-"${i}".service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
ExecReload=/bin/sleep infinity
TimeoutStartSec=infinity
EOF
    done

    systemctl daemon-reload

    echo "Starting legit unit..."
    systemctl start legit.service

    echo "Starting sus units..."
    for i in $(seq -f "%03g" 1 "$n_sus"); do
        systemctl start sus-"${i}".service
    done

    if [[ "$pending_jobs" == "with_pending_jobs" ]]; then
        # Queue a hanging reload job on each running sus unit. ExecReload runs
        # 'sleep infinity', so the reload job stays in the queue forever; the
        # unit stays active with its real MainPID, and the serialized stream
        # contains both 'main-pid=...' and 'job\n...\n\n' subsections.
        for i in $(seq -f "%03g" 1 "$n_sus"); do
            systemctl --no-block reload sus-"${i}".service
        done
        # Make sure at least one reload job is actually queued, otherwise the
        # serialized stream might not contain any job subsections yet.
        wait_for_pending_job sus-
    fi

    echo "Setup complete: 1 running legit unit, $n_sus ${pending_jobs:+job-bearing }sus units"

    orig_pid=$(systemctl show -P MainPID legit.service)
    echo "Original legit PID: $orig_pid"

    if (( orig_pid == 0 )); then
        echo "Error: Legit PID is 0, setup failed."
        return 1
    fi

    # Since ordering is not deterministic we should loop several times to
    # reduce false negative rate (ordering luck). The skip-desync regression
    # also depends on iteration order: legit.service must happen to be
    # serialized right after a job-bearing unit for its name to be dropped from
    # the collected set (which is what bypasses the alias-protection check),
    # so multiple attempts are needed in both modes.
    for attempt in 1 2 3; do
        echo ""
        echo "--- Attempt $attempt/3 ---"

        unset sus_pids
        declare -A sus_pids
        for i in $(seq -f "%03g" 1 "$n_sus"); do
            pid=$(systemctl show -P MainPID sus-"${i}".service)
            if (( pid != 0 )); then
                sus_pids["sus-${i}"]=$pid
                abandoned_pids+=("$pid")
            fi
        done

        echo "Converting sus units to symlinks -> legit.service..."
        for i in $(seq -f "%03g" 1 "$n_sus"); do
            rm -f /run/systemd/system/sus-"${i}".service
            ln -sf /run/systemd/system/legit.service /run/systemd/system/sus-"${i}".service
        done

        reload_start=$(date '+%Y-%m-%d %H:%M:%S')

        echo "Running $reload_cmd..."
        systemctl "$reload_cmd"

        # If the bug triggered, legit.service deserialized a sus unit's state
        # and overwrote its own MainPID with the sus unit's PID.
        new_pid=$(systemctl show -P MainPID legit.service)

        if [[ "$new_pid" != "$orig_pid" ]]; then
            echo "legit.service PID changed from $orig_pid to $new_pid!"
            echo "The stale alias state corrupted the canonical unit."
            return 1
        fi

        echo "legit.service PID remains $new_pid. Attempt $attempt passed."

        # Verify that all sus unit processes were tracked in a synthesized
        # orphan unit, not abandoned.
        echo "Verifying sus unit processes were migrated into synthesized orphan units..."
        for unit in "${!sus_pids[@]}"; do
            pid=${sus_pids[$unit]}
            # Process should still be running
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "ERROR: $unit process (PID $pid) was killed instead of being preserved!"
                return 1
            fi
            # The alias should now either be inactive (MainPID=0) or resolve to legit's PID.
            current_pid=$(systemctl show -P MainPID "${unit}.service")
            if ! (( current_pid == 0 || current_pid == new_pid )); then
                echo "ERROR: $unit unexpectedly reports MainPID=$current_pid after aliasing!"
                return 1
            fi
            echo "$unit process (PID $pid) is still running and the alias correctly does not claim it"
        done

        # Verify that synthesized orphan units exist that cover all the
        # previously-tracked PIDs. Each preserved process must belong to a
        # orphaned-r* unit. Orphan units retain the original unit's type
        # (.service here) and are marked load-state=not-found, so list-units
        # with --all is required to see them.
        echo "Verifying synthesized orphan units are present and own the PIDs..."
        orphan_units=$(systemctl list-units --all --no-legend --plain 'orphaned-r*' | awk '{print $1}')
        if [[ -z "$orphan_units" ]]; then
            echo "ERROR: No orphaned-r* units were synthesized!"
            systemctl list-units --all --no-legend --plain || true
            return 1
        fi
        echo "Found orphan units:"
        echo "$orphan_units"

        # Build a set of all PIDs reported by any orphan unit (via Tasks/cgroup membership).
        unset tracked_pids
        declare -A tracked_pids
        for orphan in $orphan_units; do
            orphan_cgroup=$(systemctl show -P ControlGroup "$orphan")
            if [[ -z "$orphan_cgroup" || ! -r "/sys/fs/cgroup${orphan_cgroup}/cgroup.procs" ]]; then
                # Orphan unit may have been recorded with the original unit's cgroup path which still exists
                echo "ERROR: Cannot read cgroup.procs for $orphan at expected path /sys/fs/cgroup${orphan_cgroup}/cgroup.procs"
                return 1
            fi
            while read -r p; do
                [[ -n "$p" ]] && tracked_pids[$p]=1
            done < "/sys/fs/cgroup${orphan_cgroup}/cgroup.procs"
        done

        # Cross-check: every original sus PID must appear under exactly one orphan unit cgroup.
        for unit in "${!sus_pids[@]}"; do
            pid=${sus_pids[$unit]}
            if [[ -z "${tracked_pids[$pid]:-}" ]]; then
                echo "ERROR: PID $pid (from $unit) is not tracked by any synthesized orphan unit!"
                echo "Orphan unit contents:"
                for orphan in $orphan_units; do
                    echo "  $orphan -> $(systemctl show -P ControlGroup "$orphan")"
                done
                return 1
            fi
        done
        echo "All ${#sus_pids[@]} sus PIDs are tracked by synthesized orphan units."

        # Check consistency between journal warnings and synthesized orphan units.
        echo "Checking journal for 'Synthesized orphan unit' warnings..."
        journal_warnings=$(journalctl --since "$reload_start" --no-pager | grep "Synthesized orphan unit" || true)
        warning_count=$(echo "$journal_warnings" | grep -c "Synthesized orphan unit" || true)

        echo "Found $warning_count 'Synthesized orphan unit' warnings"

        if (( warning_count > 0 )); then
            echo "Verifying warning consistency..."
            for unit in "${!sus_pids[@]}"; do
                if [[ "$journal_warnings" != *"${unit}.service"* ]]; then
                    echo "WARNING: Expected journal warning for ${unit}.service but didn't find it"
                fi
            done
        fi

        # Stop synthesized orphan units (which terminates their tracked
        # processes) so we get a clean slate for the next iteration.
        for orphan in $orphan_units; do
            systemctl stop "$orphan" 2>/dev/null || true
        done

        reap_abandoned_pids

        if (( attempt < 3 )); then
            echo "Resetting sus units..."

            # We must fully reset to get independent running units again
            for i in $(seq -f "%03g" 1 "$n_sus"); do
                rm -f /run/systemd/system/sus-"${i}".service
                cat >/run/systemd/system/sus-"${i}".service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
ExecReload=/bin/sleep infinity
TimeoutStartSec=infinity
EOF
            done

            systemctl "$reload_cmd"

            # Ensure they are running again (they might have been
            # abandoned/killed during the transition)
            for i in $(seq -f "%03g" 1 "$n_sus"); do
                systemctl start sus-"${i}".service
            done

            if [[ "$pending_jobs" == "with_pending_jobs" ]]; then
                for i in $(seq -f "%03g" 1 "$n_sus"); do
                    systemctl --no-block reload sus-"${i}".service
                done
                wait_for_pending_job sus-
            fi

            echo "Reset complete."
        fi
    done

    echo "legit.service did not become sus through all 3 $reload_cmd cycles"

    echo "$reload_cmd test passed"
}

cleanup_test_units() {
    reap_abandoned_pids || true
    # Stop any leftover synthesized orphan units from previous iterations.
    # Do this in two passes since a queued stop job from the deserialized
    # state may take a moment to dispatch and tear the unit down.
    for orphan in $(systemctl list-units --all --no-legend --plain 'orphaned-r*' 2>/dev/null | awk '{print $1}'); do
        systemctl stop "$orphan" 2>/dev/null || true
    done
    for orphan in $(systemctl list-units --all --no-legend --plain 'orphaned-r*' 2>/dev/null | awk '{print $1}'); do
        systemctl kill --signal=SIGKILL "$orphan" 2>/dev/null || true
        systemctl reset-failed "$orphan" 2>/dev/null || true
    done
    systemctl stop legit.service 2>/dev/null || true
    systemctl stop hung-stop.service 2>/dev/null || true
    for i in $(seq -f "%03g" 1 100); do
        systemctl stop sus-"${i}".service 2>/dev/null || true
        rm -f /run/systemd/system/sus-"${i}".service
    done
    rm -f /run/systemd/system/legit.service
    rm -f /run/systemd/system/hung-stop.service
    systemctl daemon-reload
}

# Verify that a JOB_STOP that was pending on the original unit at the moment of
# serialization is preserved on the synthesized orphan unit, so the stop is
# eventually carried out (the orphan is torn down) instead of sitting around
# forever.
test_stop_job_preserved() {
    local reload_cmd="${1:?}"
    local hung_pid orphan stop_job substate

    echo ""
    echo "========================================="
    echo "Testing pending-stop preservation with: systemctl $reload_cmd"
    echo "========================================="

    # Service whose main process traps SIGTERM and never exits, so a "stop"
    # request stays pending in the queue and remains serialized.
    cat >/run/systemd/system/legit.service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
    cat >/run/systemd/system/hung-stop.service <<'EOF'
[Service]
Type=notify
NotifyAccess=all
ExecStart=/bin/bash -c 'trap "" TERM; systemd-notify --ready; while :; do sleep infinity & wait $!; done'
TimeoutStopSec=infinity
SendSIGKILL=no
EOF

    systemctl daemon-reload
    systemctl start legit.service
    systemctl start hung-stop.service

    hung_pid=$(systemctl show -P MainPID hung-stop.service)
    if (( hung_pid == 0 )); then
        echo "ERROR: hung-stop.service did not start"
        return 1
    fi

    # Queue a stop that will hang because the process traps SIGTERM and
    # SendSIGKILL=no prevents escalation, so the job stays in the queue and
    # is therefore present in the serialized state at reload time.
    systemctl --no-block stop hung-stop.service
    wait_for_pending_job hung-stop.service

    # Convert hung-stop.service into a symlink to legit.service: on the next
    # reload the original unit becomes an alias of legit.service, and its
    # serialized state (including the pending stop job) is fed into the
    # synthesized orphaned-r* orphan unit.
    rm -f /run/systemd/system/hung-stop.service
    ln -sf /run/systemd/system/legit.service /run/systemd/system/hung-stop.service

    systemctl "$reload_cmd"

    orphan=$(systemctl list-units --all --no-legend --plain 'orphaned-r*' | awk '{print $1}' | head -n1)
    if [[ -z "$orphan" ]]; then
        echo "ERROR: no synthesized orphan unit was created"
        systemctl list-units --all --no-legend --plain || true
        return 1
    fi
    echo "Synthesized orphan unit: $orphan"

    # The pending stop job from the original unit must have been carried over
    # to the synthesized orphan, otherwise the orphan (and its tracked
    # process) is leaked across the reload. Check if:
    #   - the stop job is still queued,
    #   - the orphan is in a stop-* sub-state,
    #   - the orphan has already finished stopping (dead/failed),
    #   - the orphan was already garbage-collected (no SubState reported).
    stop_job=$(systemctl show -P Job "$orphan" 2>/dev/null || true)
    substate=$(systemctl show -P SubState "$orphan" 2>/dev/null || true)
    if [[ -z "$stop_job" ]] && [[ -n "$substate" ]] && ! [[ "$substate" =~ ^(stop-|dead|failed) ]]; then
        echo "ERROR: stop job for original hung-stop.service was not preserved on $orphan!"
        echo "Current substate: $substate"
        systemctl list-jobs || true
        return 1
    fi

    echo "Stop job for original hung-stop.service was correctly preserved on synthesized orphan $orphan"

    # Tear the hung orphan down for the next iteration.
    systemctl kill --signal=SIGKILL "$orphan" 2>/dev/null || true
    systemctl reset-failed "$orphan" 2>/dev/null || true
    if kill -0 "$hung_pid" 2>/dev/null; then
        kill -KILL "$hung_pid" 2>/dev/null || true
    fi

    rm -f /run/systemd/system/hung-stop.service /run/systemd/system/legit.service
    systemctl daemon-reload

    echo "$reload_cmd stop-job preservation test passed"
}

trap cleanup_test_units EXIT

run_test daemon-reload
cleanup_test_units
run_test daemon-reexec
cleanup_test_units
run_test daemon-reload with_pending_jobs
cleanup_test_units
run_test daemon-reexec with_pending_jobs
cleanup_test_units
test_stop_job_preserved daemon-reload
cleanup_test_units
test_stop_job_preserved daemon-reexec
