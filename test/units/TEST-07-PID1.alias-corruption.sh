#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# Verify that stale alias state doesn't overwrite canonical unit state.
# 1. Legit unit is running (PID A).
# 2. Sus units are running (PID B, C, D...).
# 3. We alias sus -> legit.
# 4. If the bug triggers, legit unit's state is overwritten by a sus unit's state.
# 5. Legit unit thinks it is now PID B (or C, or D...).
# 6. We detect this PID change as proof of corruption.

run_test() {
    local reload_cmd="${1:-daemon-reload}"
    echo ""
    echo "========================================="
    echo "Testing with: systemctl $reload_cmd"
    echo "========================================="

    cat >/run/systemd/system/legit.service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF

    # Create 20 sus units. They must be Type=simple/running so systemd
    # CANNOT garbage collect them. If they are dead/stopped, systemd can remove
    # them from memory before serialisation
    echo "Creating 20 sus units..."
    for i in $(seq -f "%02g" 1 20); do
        cat >/run/systemd/system/sus-"${i}".service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
    done

    systemctl "$reload_cmd"

    echo "Starting legit unit..."
    systemctl start legit.service

    echo "Starting sus units..."
    for i in $(seq -f "%02g" 1 20); do
        systemctl start sus-"${i}".service
    done

    echo "Setup complete: 1 running legit unit, 20 running sus units"

    orig_pid=$(systemctl show -p MainPID --value legit.service)
    echo "Original legit PID: $orig_pid"

    if [ "$orig_pid" -eq 0 ]; then
        echo "Error: Legit PID is 0, setup failed."
        return 1
    fi

    # Since ordering is not deterministic we should loop 3 times to reduce
    # false negative rate (ordering luck). With this it's roughly 0.01% chance
    # of falsely passing. Falsely failing does not happen, though.
    for attempt in 1 2 3; do
        echo ""
        echo "--- Attempt $attempt/3 ---"

        declare -A sus_pids
        for i in $(seq -f "%02g" 1 20); do
            pid=$(systemctl show -p MainPID --value sus-"${i}".service)
            if [ "$pid" -ne 0 ]; then
                sus_pids["sus-${i}"]=$pid
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

        # If the bug triggered, legit.service deserialised a sus unit's state
        # and overwrote its own MainPID with the sus unit's PID.
        new_pid=$(systemctl show -p MainPID --value legit.service)

        if [ "$new_pid" != "$orig_pid" ]; then
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
            # But systemd should no longer track it (MainPID should be 0 or legit's PID)
            current_pid=$(systemctl show -p MainPID --value "${unit}.service")
            if [ "$current_pid" -eq "$pid" ]; then
                echo "ERROR: $unit is still tracking PID $pid (not abandoned)!"
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
        if [ "$warning_count" -gt 0 ]; then
            echo "Verifying warning consistency..."
            for unit in "${!sus_pids[@]}"; do
                if ! echo "$journal_warnings" | grep -q "${unit}.service"; then
                    echo "WARNING: Expected journal warning for ${unit}.service but didn't find it"
                fi
            done
        fi

        if [ "$attempt" -lt 3 ]; then
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

    echo "legit.service did not become sus through all 3 $reload_cmd cycles"

    echo "$reload_cmd test passed"
}

cleanup_test_units() {
    systemctl stop legit.service 2>/dev/null || true
    for i in $(seq -f "%02g" 1 20); do
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
