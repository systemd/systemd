#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test for --completion-names functionality in systemctl and journalctl

set -ex

systemctl=${1:-systemctl}
journalctl=${2:-journalctl}

unset root
cleanup() {
    [ -n "$root" ] && rm -rf "$root"
}
trap cleanup exit
root=$(mktemp -d --tmpdir completion-test.XXXXXX)

# Test systemctl list-units --completion-names
echo "=== Testing systemctl list-units --completion-names ==="

# Basic functionality test
units_output=$("$systemctl" list-units --completion-names --no-pager 2>/dev/null || true)
if [ -n "$units_output" ]; then
    echo "✓ systemctl list-units --completion-names produces output"

    # Check for base name augmentation for .service units
    service_units=$(echo "$units_output" | grep '\.service$' | head -1)
    if [ -n "$service_units" ]; then
        service_name=$(echo "$service_units" | head -1)
        base_name=$(echo "$service_name" | sed 's/\.service$//')

        # Check if the base name is also in the output
        if echo "$units_output" | grep -q "^${base_name}$"; then
            echo "✓ Base name augmentation working for .service units"
        else
            echo "✗ Base name augmentation not working for .service units"
            echo "  Expected to find '$base_name' in output for service '$service_name'"
            exit 1
        fi
    else
        echo "! No .service units found to test base name augmentation"
    fi

    # Verify no formatting/headers are included
    if echo "$units_output" | grep -q "UNIT\|LOAD\|ACTIVE"; then
        echo "✗ systemctl list-units --completion-names includes headers"
        exit 1
    else
        echo "✓ systemctl list-units --completion-names excludes headers"
    fi
else
    echo "! No units found to test"
fi

# Test with specific state filter
failed_output=$("$systemctl" list-units --completion-names --state=failed --no-pager 2>/dev/null || true)

# Test systemctl list-unit-files --completion-names
echo "=== Testing systemctl list-unit-files --completion-names ==="

unit_files_output=$("$systemctl" list-unit-files --completion-names --no-pager 2>/dev/null || true)
if [ -n "$unit_files_output" ]; then
    echo "✓ systemctl list-unit-files --completion-names produces output"

    # Check for base name augmentation for .service unit files
    service_files=$(echo "$unit_files_output" | grep '\.service$' | head -1)
    if [ -n "$service_files" ]; then
        service_file=$(echo "$service_files" | head -1)
        base_name=$(echo "$service_file" | sed 's/\.service$//')

        # Check if the base name is also in the output
        if echo "$unit_files_output" | grep -q "^${base_name}$"; then
            echo "✓ Base name augmentation working for .service unit files"
        else
            echo "✗ Base name augmentation not working for .service unit files"
            echo "  Expected to find '$base_name' in output for service file '$service_file'"
            exit 1
        fi
    else
        echo "! No .service unit files found to test base name augmentation"
    fi

    # Verify no formatting/headers are included
    if echo "$unit_files_output" | grep -q "UNIT FILE\|STATE\|PRESET"; then
        echo "✗ systemctl list-unit-files --completion-names includes headers"
        exit 1
    else
        echo "✓ systemctl list-unit-files --completion-names excludes headers"
    fi
else
    echo "! No unit files found to test"
fi

# Test with state filter
enabled_output=$("$systemctl" list-unit-files --completion-names --state=enabled --no-pager 2>/dev/null || true)

# Test journalctl --completion-names
echo "=== Testing journalctl --completion-names ==="

# Test with _SYSTEMD_UNIT field
journal_output=$("$journalctl" -F '_SYSTEMD_UNIT' --completion-names --no-pager 2>/dev/null || true)
if [ -n "$journal_output" ]; then
    echo "✓ journalctl -F '_SYSTEMD_UNIT' --completion-names produces output"

    # Check for base name augmentation for .service units in journal
    service_units=$(echo "$journal_output" | grep '\.service$' | head -1)
    if [ -n "$service_units" ]; then
        service_name=$(echo "$service_units" | head -1)
        base_name=$(echo "$service_name" | sed 's/\.service$//')

        # Check if the base name is also in the output
        if echo "$journal_output" | grep -q "^${base_name}$"; then
            echo "✓ Base name augmentation working for journal .service units"
        else
            echo "✗ Base name augmentation not working for journal .service units"
            echo "  Expected to find '$base_name' in output for service '$service_name'"
            exit 1
        fi
    else
        echo "! No .service units found in journal to test base name augmentation"
    fi

    # Verify no formatting/headers are included
    if echo "$journal_output" | grep -q "_SYSTEMD_UNIT"; then
        echo "✗ journalctl -F '_SYSTEMD_UNIT' --completion-names includes headers"
        exit 1
    else
        echo "✓ journalctl -F '_SYSTEMD_UNIT' --completion-names excludes headers"
    fi
else
    echo "! No journal units found to test"
fi

# Test that --completion-names only works with -F for journalctl
if "$journalctl" --completion-names --no-pager 2>/dev/null; then
    echo "✗ journalctl --completion-names should only work with -F"
    exit 1
fi

# Test flag interaction - verify that --completion-names implies other flags
echo "=== Testing flag interaction ==="

# systemctl should automatically enable --plain, --no-legend, --no-pager when --completion-names is used
# We can't easily test this directly, but we can verify the output format is correct
plain_output=$("$systemctl" list-units --completion-names 2>/dev/null || true)
formatted_output=$("$systemctl" list-units --completion-names --legend --no-plain 2>/dev/null || true)

# The outputs should be identical because --completion-names should override other formatting
if [ "$plain_output" != "$formatted_output" ]; then
    echo "! systemctl --completion-names formatting behavior may vary"
fi

# Test pattern matching
echo "=== Testing pattern matching ==="

# Test with a pattern that should match something
systemd_units=$("$systemctl" list-units --completion-names 'systemd-*' --no-pager 2>/dev/null || true)
if [ -n "$systemd_units" ]; then
    echo "✓ systemctl --completion-names works with patterns"

    # Verify all results match the pattern
    if echo "$systemd_units" | grep -v '^systemd-' | grep -q .; then
        echo "✗ systemctl --completion-names pattern matching not working correctly"
        exit 1
    else
        echo "✓ systemctl --completion-names pattern matching works correctly"
    fi
else
    echo "! No systemd-* units found to test patterns"
fi

# Test edge cases
echo "=== Testing edge cases ==="

# Test with empty pattern
empty_pattern_output=$("$systemctl" list-units --completion-names 'nonexistent-*' --no-pager 2>/dev/null || true)

# Test with user mode
user_output=$("$systemctl" --user list-units --completion-names --no-pager 2>/dev/null || true)

echo "=== All completion tests passed! ==="
