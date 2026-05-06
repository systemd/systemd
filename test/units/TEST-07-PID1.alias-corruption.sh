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
    local current_pid journal_warnings new_pid orig_pid pid reload_start unit warning_count

    echo ""
    echo "========================================="
    echo "Testing with: systemctl $reload_cmd${pending_jobs:+ ($pending_jobs)}"
    echo "========================================="

    cat >/run/systemd/system/legit.service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF

    # Create 20 sus units. They must be Type=simple/running so systemd
    # CANNOT garbage collect them. If they are dead/stopped, systemd can remove
    # them from memory before serialization
    echo "Creating 20 sus units..."
    for i in $(seq -f "%02g" 1 20); do
        cat >/run/systemd/system/sus-"${i}".service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
    done

    systemctl daemon-reload

    echo "Starting legit unit..."
    systemctl start legit.service

    echo "Starting sus units..."
    for i in $(seq -f "%02g" 1 20); do
        systemctl start sus-"${i}".service
    done

    if [[ "$pending_jobs" == "with_pending_jobs" ]]; then
        echo "Creating 50 units with pending jobs..."
        for i in $(seq -f "%02g" 1 50); do
            cat >/run/systemd/system/stuck-"${i}".service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/sleep infinity
TimeoutStartSec=infinity
EOF
        done
        systemctl daemon-reload
        # --no-block leaves a pending start job that stays "activating" forever,
        # so u->job is non-NULL when serialization runs.
        for i in $(seq -f "%02g" 1 50); do
            systemctl --no-block start stuck-"${i}".service
        done
        # --no-block returns 0 as soon as the job is queued, so confirm the
        # precondition (pending jobs actually exist) before exercising the
        # deserialization path. Use 'systemctl show' rather than 'is-active':
        # the latter exits non-zero for "activating", which trips pipefail.
        for i in $(seq 1 100); do
            if [[ "$(systemctl show -P ActiveState stuck-01.service)" == "activating" ]]; then
                break
            fi
            sleep 0.1
        done
        if [[ "$(systemctl show -P ActiveState stuck-01.service)" != "activating" ]]; then
            echo "ERROR: stuck-01.service did not reach activating state"
            systemctl status stuck-01.service || true
            return 1
        fi
    fi

    echo "Setup complete: 1 running legit unit, 20 running sus units${pending_jobs:+, 50 stuck units with pending jobs}"

    orig_pid=$(systemctl show -P MainPID legit.service)
    echo "Original legit PID: $orig_pid"

    if (( orig_pid == 0 )); then
        echo "Error: Legit PID is 0, setup failed."
        return 1
    fi

    # Since ordering is not deterministic we should loop 3 times to reduce
    # false negative rate (ordering luck). With this it's roughly 0.01% chance
    # of falsely passing. Falsely failing does not happen, though.
    # The pending-jobs variant is deterministic though so a single attempt is enough
    local attempts=3
    if [[ "$pending_jobs" == "with_pending_jobs" ]]; then
        attempts=1
    fi

    for attempt in $(seq 1 "$attempts"); do
        echo ""
        echo "--- Attempt $attempt/$attempts ---"

        unset sus_pids
        declare -A sus_pids
        for i in $(seq -f "%02g" 1 20); do
            pid=$(systemctl show -P MainPID sus-"${i}".service)
            if (( pid != 0 )); then
                sus_pids["sus-${i}"]=$pid
                abandoned_pids+=("$pid")
                echo "sus-${i}.service PID: $pid"
            fi
        done

        echo "Converting sus units to symlinks -> legit.service..."
        for i in $(seq -f "%02g" 1 20); do
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

        if (( attempt < attempts )); then
            echo "Resetting sus units..."

            # We must fully reset to get independent running units again
            for i in $(seq -f "%02g" 1 20); do
                rm -f /run/systemd/system/sus-"${i}".service
                cat >/run/systemd/system/sus-"${i}".service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
            done

            systemctl "$reload_cmd"

            # Ensure they are running again (they might have been
            # abandoned/killed during the transition)
            for i in $(seq -f "%02g" 1 20); do
                systemctl start sus-"${i}".service
            done

            echo "Reset complete."
        fi
    done

    echo "legit.service did not become sus through all $attempts $reload_cmd cycles"

    echo "$reload_cmd test passed"
}

cleanup_test_units() {
    reap_abandoned_pids || true
    systemctl stop legit.service 2>/dev/null || true
    for i in $(seq -f "%02g" 1 20); do
        systemctl stop sus-"${i}".service 2>/dev/null || true
        rm -f /run/systemd/system/sus-"${i}".service
    done
    if [[ -e /run/systemd/system/stuck-01.service ]]; then
        for i in $(seq -f "%02g" 1 50); do
            systemctl stop stuck-"${i}".service 2>/dev/null || true
            rm -f /run/systemd/system/stuck-"${i}".service
        done
    fi
    rm -f /run/systemd/system/legit.service
    systemctl daemon-reload
}

trap cleanup_test_units EXIT

run_test daemon-reload
cleanup_test_units
run_test daemon-reexec
cleanup_test_units
run_test daemon-reexec with_pending_jobs
