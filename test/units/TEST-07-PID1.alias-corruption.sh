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

setup_test_units() {
    cat > /run/systemd/system/legit.service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF

    # Create 20 sus units. They must be Type=simple/running so systemd
    # CANNOT garbage collect them. If they are dead/stopped, systemd can remove
    # them from memory before serialisation, preventing the bug from
    # manifesting.
    echo "Creating 20 sus units..."
    for i in $(seq -f "%02g" 1 20); do
        cat > /run/systemd/system/sus-"${i}".service <<'EOF'
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

    echo "Setup complete: 1 running legit unit, 20 running sus units"
}

trigger_bug() {
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

        echo "Converting sus units to symlinks -> legit.service..."
        for i in $(seq -f "%02g" 1 20); do
            rm -f /run/systemd/system/sus-"${i}".service
            ln -sf /run/systemd/system/legit.service /run/systemd/system/sus-"${i}".service
        done

        echo "Running daemon-reload..."
        systemctl daemon-reload

        # If the bug triggered, legit.service deserialised a sus unit's state
        # and overwrote its own MainPID with the sus unit's PID.
        new_pid=$(systemctl show -p MainPID --value legit.service)

        if [ "$new_pid" != "$orig_pid" ]; then
            echo "legit.service PID changed from $orig_pid to $new_pid!"
            echo "The stale alias state corrupted the canonical unit."
            return 1
        fi

        echo "legit.service PID remains $new_pid. Attempt $attempt passed."

        if [ "$attempt" -lt 3 ]; then
            echo "Resetting sus units..."

            # We must fully reset to get independent running units again
            for i in $(seq -f "%02g" 1 20); do
                rm -f /run/systemd/system/sus-"${i}".service
                cat > /run/systemd/system/sus-"${i}".service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
            done

            systemctl daemon-reload

            # Ensure they are running again (they might have been
            # abandoned/killed during the transition)
            for i in $(seq -f "%02g" 1 20); do
                systemctl start sus-"${i}".service
            done

            echo "Reset complete."
        fi
    done

    echo "legit.service did not become sus through all 3 reload cycles"
    return 0
}

verify_result() {
    warning_count=$(journalctl --since "5 minutes ago" --no-pager | grep -c "Skipping stale state" || true)

    echo "Found $warning_count 'Skipping stale state' warnings in journal"

    if [ "$warning_count" -eq 0 ]; then
        echo "WARNING: Test passed but no fix logs were found."
        echo "This suggests the fix might not be active or the swarm size is too small."
        # ...but don't fail it, because it could be a false negative
    fi

    echo "Alias corruption test passed"
    return 0
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

setup_test_units
trigger_bug
verify_result
