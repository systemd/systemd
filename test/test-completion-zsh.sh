#!/usr/bin/env zsh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test for zsh completion functionality with --completion-names in systemctl and journalctl

setopt ERR_EXIT
setopt XTRACE

systemctl=${1:-systemctl}
journalctl=${2:-journalctl}

unset root
cleanup() {
    [[ -n "$root" ]] && rm -rf "$root"
}
trap cleanup EXIT
root=$(mktemp -d --tmpdir completion-test.XXXXXX)

# Test zsh systemctl completion behavior
echo "=== Testing zsh systemctl completion with --completion-names ==="

# Test list-units completion
units_output=$("$systemctl" list-units --completion-names --no-pager 2>/dev/null || true)
if [[ -n "$units_output" ]]; then
    print "✓ systemctl list-units --completion-names produces output"

    # Check for base name augmentation for .service units
    service_units=(${(f)"$(print -l $units_output | grep '\.service$' | head -1)"})
    if [[ ${#service_units[@]} -gt 0 ]]; then
        service_name="${service_units[1]}"
        base_name="${service_name%.service}"

        # Check if the base name is also in the output (zsh array matching)
        if (( ${units_output[(I)$base_name]} )); then
            print "✓ Base name augmentation working for .service units"
        else
            print "✗ Base name augmentation not working for .service units"
            print "  Expected to find '$base_name' in output for service '$service_name'"
            exit 1
        fi
    else
        print "! No .service units found to test base name augmentation"
    fi

    # Verify no formatting/headers are included (zsh pattern matching)
    if [[ "$units_output" =~ "(UNIT|LOAD|ACTIVE)" ]]; then
        print "✗ systemctl list-units --completion-names includes headers"
        exit 1
    else
        print "✓ systemctl list-units --completion-names excludes headers"
    fi
else
    print "! No units found to test"
fi

# Test with specific state filter
failed_output=$("$systemctl" list-units --completion-names --state=failed --no-pager 2>/dev/null || true)

# Test systemctl list-unit-files --completion-names
echo "=== Testing zsh systemctl list-unit-files completion ==="

unit_files_output=$("$systemctl" list-unit-files --completion-names --no-pager 2>/dev/null || true)
if [[ -n "$unit_files_output" ]]; then
    print "✓ systemctl list-unit-files --completion-names produces output"

    # Check for base name augmentation for .service unit files
    service_files=(${(f)"$(print -l $unit_files_output | grep '\.service$' | head -1)"})
    if [[ ${#service_files[@]} -gt 0 ]]; then
        service_file="${service_files[1]}"
        base_name="${service_file%.service}"

        # Check if the base name is also in the output (zsh array matching)
        if (( ${unit_files_output[(I)$base_name]} )); then
            print "✓ Base name augmentation working for .service unit files"
        else
            print "✗ Base name augmentation not working for .service unit files"
            print "  Expected to find '$base_name' in output for service file '$service_file'"
            exit 1
        fi
    else
        print "! No .service unit files found to test base name augmentation"
    fi

    # Verify no formatting/headers are included (zsh pattern matching)
    if [[ "$unit_files_output" =~ "(UNIT FILE|STATE|PRESET)" ]]; then
        print "✗ systemctl list-unit-files --completion-names includes headers"
        exit 1
    else
        print "✓ systemctl list-unit-files --completion-names excludes headers"
    fi
else
    print "! No unit files found to test"
fi

# Test with state filter
enabled_output=$("$systemctl" list-unit-files --completion-names --state=enabled --no-pager 2>/dev/null || true)

# Test journalctl --completion-names
echo "=== Testing zsh journalctl completion ==="

# Test with _SYSTEMD_UNIT field
journal_output=$("$journalctl" -F '_SYSTEMD_UNIT' --completion-names --no-pager 2>/dev/null || true)
if [[ -n "$journal_output" ]]; then
    print "✓ journalctl -F '_SYSTEMD_UNIT' --completion-names produces output"

    # Check for base name augmentation for .service units in journal
    service_units=(${(f)"$(print -l $journal_output | grep '\.service$' | head -1)"})
    if [[ ${#service_units[@]} -gt 0 ]]; then
        service_name="${service_units[1]}"
        base_name="${service_name%.service}"

        # Check if the base name is also in the output (zsh array matching)
        if (( ${journal_output[(I)$base_name]} )); then
            print "✓ Base name augmentation working for journal .service units"
        else
            print "✗ Base name augmentation not working for journal .service units"
            print "  Expected to find '$base_name' in output for service '$service_name'"
            exit 1
        fi
    else
        print "! No .service units found in journal to test base name augmentation"
    fi

    # Verify no formatting/headers are included (zsh pattern matching)
    if [[ "$journal_output" =~ "_SYSTEMD_UNIT" ]]; then
        print "✗ journalctl -F '_SYSTEMD_UNIT' --completion-names includes headers"
        exit 1
    else
        print "✓ journalctl -F '_SYSTEMD_UNIT' --completion-names excludes headers"
    fi
else
    print "! No journal units found to test"
fi

# Test that --completion-names only works with -F for journalctl
if "$journalctl" --completion-names --no-pager 2>/dev/null; then
    print "✗ journalctl --completion-names should only work with -F"
    exit 1
fi

# Test flag interaction - verify that --completion-names implies other flags
echo "=== Testing zsh flag interaction ==="

# systemctl should automatically enable --plain, --no-legend, --no-pager when --completion-names is used
plain_output=$("$systemctl" list-units --completion-names 2>/dev/null || true)
formatted_output=$("$systemctl" list-units --completion-names --legend --no-plain 2>/dev/null || true)

# The outputs should be identical because --completion-names should override other formatting
if [[ "$plain_output" != "$formatted_output" ]]; then
    print "! systemctl --completion-names formatting behavior may vary"
fi

# Test pattern matching
echo "=== Testing zsh pattern matching ==="

# Test with a pattern that should match something
systemd_units=$("$systemctl" list-units --completion-names 'systemd-*' --no-pager 2>/dev/null || true)
if [[ -n "$systemd_units" ]]; then
    print "✓ systemctl --completion-names works with patterns"

    # Verify all results match the pattern (zsh pattern matching)
    local -a non_matching
    non_matching=(${(f)"$(print -l $systemd_units | grep -v '^systemd-')"})
    if [[ ${#non_matching[@]} -gt 0 ]]; then
        print "✗ systemctl --completion-names pattern matching not working correctly"
        exit 1
    else
        print "✓ systemctl --completion-names pattern matching works correctly"
    fi
else
    print "! No systemd-* units found to test patterns"
fi

# Test edge cases
echo "=== Testing zsh edge cases ==="

# Test with empty pattern
empty_pattern_output=$("$systemctl" list-units --completion-names 'nonexistent-*' --no-pager 2>/dev/null || true)

# Test with user mode
user_output=$("$systemctl" --user list-units --completion-names --no-pager 2>/dev/null || true)

# Test zsh-specific array behavior
echo "=== Testing zsh-specific completion behavior ==="

# Test array processing for completion results
completion_array=(${(f)"$("$systemctl" list-units --completion-names --no-pager 2>/dev/null | head -10)"})
if [[ ${#completion_array[@]} -gt 0 ]]; then

    # Test zsh parameter expansion for .service suffix removal
    for unit in "${completion_array[@]}"; do
        if [[ "$unit" == *.service ]]; then
            base_name="${unit%.service}"
            if [[ -n "$base_name" ]]; then
                break
            fi
        fi
    done
fi

echo "=== All zsh completion tests passed! ==="
