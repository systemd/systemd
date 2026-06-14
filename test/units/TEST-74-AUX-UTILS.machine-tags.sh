#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC1091
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v hostnamectl >/dev/null; then
    echo "hostnamectl not found, skipping the test"
    exit 0
fi

at_exit() {
    set +e

    # Restore the original /etc/machine-info (if any) and make hostnamed read it again
    if [[ -e /tmp/machine-info.bak ]]; then
        mv /tmp/machine-info.bak /etc/machine-info
    else
        rm -f /etc/machine-info
    fi
    systemctl stop --job-mode=replace-irreversibly systemd-hostnamed.service
    systemctl reset-failed systemd-hostnamed.service

    rm -fr "${ROOT:-}"
}

trap at_exit EXIT

# Read the TAGS= field out of /etc/machine-info (robust against the file being
# absent and against TAGS= being unset).
get_tags_from_file() (
    set +u
    [[ -f /etc/machine-info ]] && . /etc/machine-info
    echo "${TAGS:-}"
)

if [[ -f /etc/machine-info ]]; then
    cp /etc/machine-info /tmp/machine-info.bak
fi

# Start from a clean slate, and make sure hostnamed re-reads the (now missing) file.
rm -f /etc/machine-info
systemctl stop --job-mode=replace-irreversibly systemd-hostnamed.service || :
systemctl reset-failed systemd-hostnamed.service || :

# --------------------------------------------------------------------------------------------------
# hostnamectl tags <-> /etc/machine-info
# --------------------------------------------------------------------------------------------------

# No tags are configured initially.
assert_eq "$(hostnamectl tags)" ""

# Set some tags. Multiple arguments, colon-separated arguments, duplicates and arbitrary order are
# all accepted and normalized into a sorted, deduplicated, colon-separated list.
hostnamectl tags webserver:frontend frontend berlin
assert_eq "$(hostnamectl tags)" "berlin:frontend:webserver"

# The very same list must show up in the TAGS= field of /etc/machine-info.
grep -qE '^TAGS="?berlin:frontend:webserver"?$' /etc/machine-info
assert_eq "$(get_tags_from_file)" "berlin:frontend:webserver"

# Setting tags again replaces the previous list rather than extending it.
hostnamectl tags database
assert_eq "$(hostnamectl tags)" "database"
assert_eq "$(get_tags_from_file)" "database"

# Invalid tags (only ASCII alphanumerics, '-' and '.' are allowed) are refused, leaving the
# previously configured tags untouched.
(! hostnamectl tags "invalid tag")
(! hostnamectl tags "invalid/tag")
assert_eq "$(hostnamectl tags)" "database"

# Clearing all tags via a single empty string argument. When TAGS= was the only field, hostnamed
# removes /etc/machine-info altogether.
hostnamectl tags ""
assert_eq "$(hostnamectl tags)" ""
assert_eq "$(get_tags_from_file)" ""

# --------------------------------------------------------------------------------------------------
# ConditionMachineTag=/AssertMachineTag= in a transient unit
# --------------------------------------------------------------------------------------------------

hostnamectl tags alpha:beta:gamma
assert_eq "$(hostnamectl tags)" "alpha:beta:gamma"

# When the condition matches, the unit is started and 'false' actually runs, so systemd-run fails.
# When the condition does not match, the unit is skipped (not failed) and systemd-run succeeds.
(! systemd-run --wait --pipe -p ConditionMachineTag=beta false)
systemd-run --wait --pipe -p ConditionMachineTag=delta false
# Globs are matched against each individual tag.
(! systemd-run --wait --pipe -p ConditionMachineTag='al*' false)
systemd-run --wait --pipe -p ConditionMachineTag='z*' false
# Negation inverts the result.
systemd-run --wait --pipe -p ConditionMachineTag='!beta' false
(! systemd-run --wait --pipe -p ConditionMachineTag='!delta' false)

# Asserts behave like conditions, except a failing assert puts the unit into a failed state, which
# systemd-run propagates as a non-zero exit code.
systemd-run -p AssertMachineTag=beta -p Type=oneshot true
(! systemd-run -p AssertMachineTag=delta -p Type=oneshot true)

# --------------------------------------------------------------------------------------------------
# systemd-firstboot --machine-tags= and the firstboot.machine-tags credential
# --------------------------------------------------------------------------------------------------

if command -v systemd-firstboot >/dev/null; then
    # The firstboot.machine-tags credential is split on ':', deduplicated and sorted, and written
    # into /etc/machine-info underneath the target root.
    ROOT="$(mktemp -d)"
    systemd-run --wait --pipe --service-type=exec \
        -p SetCredential=firstboot.machine-tags:webserver:frontend:webserver:berlin \
        systemd-firstboot --root="$ROOT"
    grep -qE '^TAGS="?berlin:frontend:webserver"?$' "$ROOT/etc/machine-info"

    # An invalid tag anywhere in the credential causes the whole list to be ignored, so no
    # machine-info file is written.
    rm -fr "$ROOT"
    ROOT="$(mktemp -d)"
    systemd-run --wait --pipe --service-type=exec \
        -p SetCredential=firstboot.machine-tags:'good:bad/tag' \
        systemd-firstboot --root="$ROOT"
    test ! -e "$ROOT/etc/machine-info"

    # The --machine-tags= switch is normalized the same way and takes precedence over the credential.
    rm -fr "$ROOT"
    ROOT="$(mktemp -d)"
    systemd-run --wait --pipe --service-type=exec \
        -p SetCredential=firstboot.machine-tags:ignored \
        systemd-firstboot --root="$ROOT" --machine-tags=database:cache:database
    grep -qE '^TAGS="?cache:database"?$' "$ROOT/etc/machine-info"

    # An invalid tag passed on the command line is a hard error.
    rm -fr "$ROOT"
    ROOT="$(mktemp -d)"
    (! systemd-firstboot --root="$ROOT" --machine-tags='good:bad/tag')
fi
