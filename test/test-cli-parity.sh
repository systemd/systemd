#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Run the C and the Rust twin of the command line test program with the same arguments and require the
# same stdout, the same stderr and the same exit status, byte for byte.
#
# Usage: test-cli-parity.sh C_BINARY RUST_BINARY
set -eu
set -o pipefail

C="${1:?}"
RUST="${2:?}"

export SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0 SYSTEMD_LOG_LEVEL=info SYSTEMD_PAGER=cat COLUMNS=80 TERM=dumb
unset PAGER LESS

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Error messages contain program_invocation_short_name, so both run under the same name.
mkdir "$tmp/c" "$tmp/rust"
ln -s "$(realpath "$C")" "$tmp/c/test-cli"
ln -s "$(realpath "$RUST")" "$tmp/rust/test-cli"

failed=0
n=0

check() {
    n=$((n + 1))
    for which in c rust; do
        set +e
        "$tmp/$which/test-cli" "$@" >"$tmp/$which.out" 2>"$tmp/$which.err"
        echo "$?" >"$tmp/$which.status"
        set -e
    done

    local bad=0
    for what in out err status; do
        if ! cmp -s "$tmp/c.$what" "$tmp/rust.$what"; then
            bad=1
            echo "*** test-cli $* — $what differs (< C, > Rust):"
            diff "$tmp/c.$what" "$tmp/rust.$what" || :
        fi
    done
    if [[ $bad -eq 1 ]]; then
        failed=$((failed + 1))
    fi

    # Both must have produced something to compare, or the run is hollow.
    if ! grep . "$tmp/c.out" "$tmp/c.err" >/dev/null; then
        echo "*** test-cli $* — no output at all"
        failed=$((failed + 1))
    fi
}

check --help
check -h
check help
check --version
check --introspect-cli
check --json=short --introspect-cli
check --no-such-option
check -x
check --frob
check --frob=bar
check --frob bar status
check --fro=bar status
check --no status
check --verb status
check
check status
check status extra
check show
check show a
check show a b
check show a b c
check unknown
check sho a
check -j status
check --json=pretty status
check --json=bogus
check --json=help
check -v status
check status -v
check -vv -f x -f y status
check -- --help
check -- status --verbose
check fail
check fail more
check --plumb status
check --plumb=3 status
check --plumb 3 status
check --no-pager --no-legend -vf x show y
check --help --version
check --version --help

echo "$n invocations compared, $failed differ"
exit $((failed > 0))
