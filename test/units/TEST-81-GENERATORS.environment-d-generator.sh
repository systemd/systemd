#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator"
CONFIG_FILE="/run/environment.d/99-test.conf"
OUT_FILE="$(mktemp)"

at_exit() {
    set +e
    rm -frv "${CONFIG_FILE:?}" "${OUT_FILE:?}"
    systemctl -M testuser@.host --user daemon-reload
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"
mkdir -p /run/environment.d/

cat >"$CONFIG_FILE" <<EOF

\t\n\t
3
=
    =
INVALID
ALSO_INVALID=
EMPTY_INVALID=""
3_INVALID=foo
xxxx xx xxxxxx
# This is a comment
$(printf "%.0sx" {0..4096})=
SIMPLE=foo
REF=\$SIMPLE
ALSO_REF=\${SIMPLE}
DEFAULT="\${NONEXISTENT:-default value}"
ALTERNATE="\${SIMPLE:+alternate value}"
LIST=foo,bar,baz
SIMPLE=redefined
UNASSIGNED=\$FOO_BAR_BAZ
VERY_LONG="very $(printf "%.0sx" {0..4096})= long string"
EOF

# Source env assignments from a file and check them - do this in a subshell
# to not pollute the test environment
check_environment() {(
    # shellcheck source=/dev/null
    source "${1:?}"

    [[ "$SIMPLE" == "redefined" ]]
    [[ "$REF" == "foo" ]]
    [[ "$ALSO_REF" == "foo" ]]
    [[ "$DEFAULT" == "default value" ]]
    [[ "$ALTERNATE" == "alternate value" ]]
    [[ "$LIST" == "foo,bar,baz" ]]
    [[ "$VERY_LONG" =~ ^very\  ]]
    [[ "$VERY_LONG" =~ \ long\ string$ ]]
    [[ -z "$UNASSIGNED" ]]
    [[ ! -v INVALID ]]
    [[ ! -v ALSO_INVALID ]]
    [[ ! -v EMPTY_INVALID ]]
    [[ ! -v 3_INVALID ]]
)}

# Check the output by directly calling the generator
"$GENERATOR_BIN" | tee "$OUT_FILE"
check_environment "$OUT_FILE"
: >"$OUT_FILE"

# Check if the generator is correctly called in a user session
systemctl -M testuser@.host --user daemon-reload
systemctl -M testuser@.host --user show-environment | tee "$OUT_FILE"
check_environment "$OUT_FILE"

(! "$GENERATOR_BIN" foo)
