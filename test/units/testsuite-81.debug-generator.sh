#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-debug-generator"
OUT_DIR="$(mktemp -d /tmp/debug-generator.XXX)"

at_exit() {
    rm -frv "${OUT_DIR:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

# Potential FIXME:
#   - debug-generator should gracefully handle duplicated mask/wants
#   - also, handle gracefully empty mask/wants
ARGS=(
    "systemd.mask=masked-no-suffix"
    "systemd.mask=masked.service"
    "systemd.mask=masked.socket"
    "systemd.wants=wanted-no-suffix"
    "systemd.wants=wanted.service"
    "systemd.wants=wanted.mount"
    "rd.systemd.mask=masked-initrd.service"
    "rd.systemd.wants=wanted-initrd.service"
)

# Regular (non-initrd) scenario
#
: "debug-shell: regular"
CMDLINE="ro root=/ ${ARGS[*]} rd.systemd.debug_shell"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_eq "$OUT_DIR/masked-no-suffix.service" /dev/null
link_eq "$OUT_DIR/masked.service" /dev/null
link_eq "$OUT_DIR/masked.socket" /dev/null
link_endswith "$OUT_DIR/default.target.wants/wanted-no-suffix.service" /lib/systemd/system/wanted-no-suffix.service
link_endswith "$OUT_DIR/default.target.wants/wanted.service" /lib/systemd/system/wanted.service
link_endswith "$OUT_DIR/default.target.wants/wanted.mount" /lib/systemd/system/wanted.mount
# Following stuff should be ignored, as it's prefixed with rd.
(! test -h "$OUT_DIR/masked-initrd.service")
(! test -h "$OUT_DIR/default.target.wants/wants-initrd.service")
(! test -h "$OUT_DIR/default.target.wants/debug-shell.service")
(! test -d "$OUT_DIR/initrd.target.wants")

# Let's re-run the generator with systemd.debug_shell that should be honored
: "debug-shell: regular + systemd.debug_shell"
CMDLINE="$CMDLINE systemd.debug_shell"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/default.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service

# Same thing, but with custom tty
: "debug-shell: regular + systemd.debug_shell=/dev/tty666"
CMDLINE="$CMDLINE systemd.debug_shell=/dev/tty666"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/default.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service
grep -F "/dev/tty666" "$OUT_DIR/debug-shell.service.d/50-tty.conf"

# Now override the default target via systemd.unit=
: "debug-shell: regular + systemd.unit="
CMDLINE="$CMDLINE systemd.unit=my-fancy.target"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_eq "$OUT_DIR/masked-no-suffix.service" /dev/null
link_eq "$OUT_DIR/masked.service" /dev/null
link_eq "$OUT_DIR/masked.socket" /dev/null
link_endswith "$OUT_DIR/my-fancy.target.wants/wanted-no-suffix.service" /lib/systemd/system/wanted-no-suffix.service
link_endswith "$OUT_DIR/my-fancy.target.wants/wanted.service" /lib/systemd/system/wanted.service
link_endswith "$OUT_DIR/my-fancy.target.wants/wanted.mount" /lib/systemd/system/wanted.mount
link_endswith "$OUT_DIR/my-fancy.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service
(! test -d "$OUT_DIR/default.target.wants")


# Initrd scenario
: "debug-shell: initrd"
CMDLINE="ro root=/ ${ARGS[*]} systemd.debug_shell"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_eq "$OUT_DIR/masked-initrd.service" /dev/null
link_endswith "$OUT_DIR/initrd.target.wants/wanted-initrd.service" /lib/systemd/system/wanted-initrd.service
# The non-initrd stuff (i.e. without the rd. suffix) should be ignored in
# this case
(! test -h "$OUT_DIR/masked-no-suffix.service")
(! test -h "$OUT_DIR/masked.service")
(! test -h "$OUT_DIR/masked.socket")
(! test -h "$OUT_DIR/initrd.target.wants/debug-shell.service")
(! test -d "$OUT_DIR/default.target.wants")

# Again, but with rd.systemd.debug_shell
: "debug-shell: initrd + rd.systemd.debug_shell"
CMDLINE="$CMDLINE rd.systemd.debug_shell"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/initrd.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service

# Override the default target
: "debug-shell: initrd + rd.systemd.unit"
CMDLINE="$CMDLINE rd.systemd.unit=my-fancy-initrd.target"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_eq "$OUT_DIR/masked-initrd.service" /dev/null
link_endswith "$OUT_DIR/my-fancy-initrd.target.wants/wanted-initrd.service" /lib/systemd/system/wanted-initrd.service
(! test -d "$OUT_DIR/initrd.target.wants")
