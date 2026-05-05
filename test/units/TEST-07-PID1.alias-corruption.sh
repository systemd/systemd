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

run_test() {
    local reload_cmd="${1:?}"
    # If "with_pending_jobs", also create many Type=oneshot units that hang in
    # "activating" state with a pending job, to ensure that the serialized state
    # contains embedded "job" subsections to fully exercise the deserialization
    local pending_jobs="${2:-}"
    local n_sus=20
    local current_pid journal_warnings new_pid orig_pid pid reload_start unit warning_count

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
    # In with_pending_jobs mode they additionally get a pending restart job
    # queued via 'systemctl --no-block restart' AFTER they are running, so the
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
        for i in {1..100}; do
            [[ -n "$(systemctl list-jobs --no-legend | grep -E '^[[:space:]]*[0-9]+ sus-' || true)" ]] && break
            if (( i == 100 )); then
                echo "ERROR: no sus-*.service reload jobs are pending"
                systemctl list-jobs || true
                return 1
            fi
            sleep 0.1
        done
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

        # Verify that all sus unit processes were abandoned (still running but no longer tracked)
        echo "Verifying sus unit processes were abandoned..."
        for unit in "${!sus_pids[@]}"; do
            pid=${sus_pids[$unit]}
            # Process should still be running
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "ERROR: $unit process (PID $pid) was killed instead of abandoned!"
                return 1
            fi
            # But the alias should now either be inactive (MainPID=0) or resolve to legit's PID.
            current_pid=$(systemctl show -P MainPID "${unit}.service")
            if ! (( current_pid == 0 || current_pid == new_pid )); then
                echo "ERROR: $unit unexpectedly reports MainPID=$current_pid after aliasing!"
                return 1
            fi
            echo "$unit process (PID $pid) was correctly abandoned (still running, no longer tracked)"
        done

        # Check consistency between journal warnings and abandoned processes
        echo "Checking journal for stale state warnings..."
        journal_warnings=$(journalctl --since "$reload_start" --no-pager | grep "Skipping stale state" || true)
        warning_count=$(echo "$journal_warnings" | grep -c "Skipping stale state" || true)

        echo "Found $warning_count 'Skipping stale state' warnings"

        # Extract unit names from warnings and verify they match our sus units
        if (( warning_count > 0 )); then
            echo "Verifying warning consistency..."
            for unit in "${!sus_pids[@]}"; do
                if [[ "$journal_warnings" != *"${unit}.service"* ]]; then
                    echo "WARNING: Expected journal warning for ${unit}.service but didn't find it"
                fi
            done
        fi

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
                for i in {1..100}; do
                    [[ -n "$(systemctl list-jobs --no-legend | grep -E '^[[:space:]]*[0-9]+ sus-' || true)" ]] && break
                    if (( i == 100 )); then
                        echo "ERROR: no sus-*.service reload jobs are pending after reset"
                        systemctl list-jobs || true
                        return 1
                    fi
                    sleep 0.1
                done
            fi

            echo "Reset complete."
        fi
    done

    echo "legit.service did not become sus through all 3 $reload_cmd cycles"

    echo "$reload_cmd test passed"
}

cleanup_test_units() {
    reap_abandoned_pids || true
    systemctl stop legit.service 2>/dev/null || true
    for i in $(seq -f "%03g" 1 100); do
        systemctl stop sus-"${i}".service 2>/dev/null || true
        rm -f /run/systemd/system/sus-"${i}".service
    done
    rm -f /run/systemd/system/legit.service
    systemctl daemon-reload
}

trap cleanup_test_units EXIT

run_test daemon-reload
cleanup_test_units
run_test daemon-reexec
cleanup_test_units
run_test daemon-reload with_pending_jobs
cleanup_test_units
run_test daemon-reexec with_pending_jobs
