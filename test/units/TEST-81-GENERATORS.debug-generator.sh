#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
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
link_eq "$OUT_DIR/early/masked-no-suffix.service" /dev/null
link_eq "$OUT_DIR/early/masked.service" /dev/null
link_eq "$OUT_DIR/early/masked.socket" /dev/null
link_endswith "$OUT_DIR/early/default.target.wants/wanted-no-suffix.service" /lib/systemd/system/wanted-no-suffix.service
link_endswith "$OUT_DIR/early/default.target.wants/wanted.service" /lib/systemd/system/wanted.service
link_endswith "$OUT_DIR/early/default.target.wants/wanted.mount" /lib/systemd/system/wanted.mount
# Following stuff should be ignored, as it's prefixed with rd.
test ! -h "$OUT_DIR/early/masked-initrd.service"
test ! -h "$OUT_DIR/early/default.target.wants/wants-initrd.service"
test ! -h "$OUT_DIR/early/default.target.wants/debug-shell.service"
test ! -d "$OUT_DIR/early/initrd.target.wants"

# Let's re-run the generator with systemd.debug_shell that should be honored
: "debug-shell: regular + systemd.debug_shell"
CMDLINE="$CMDLINE systemd.debug_shell"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/default.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service

# Same thing, but with custom tty
: "debug-shell: regular + systemd.debug_shell=/dev/tty666"
CMDLINE="$CMDLINE systemd.debug_shell=/dev/tty666"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/default.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service
grep -F "/dev/tty666" "$OUT_DIR/early/debug-shell.service.d/50-tty.conf"

# Same thing, but with custom tty using systemd.default_debug_tty
: "debug-shell: regular + systemd.default_debug_tty=/dev/tty666 systemd.debug_shell=yes"
CMDLINE="$CMDLINE systemd.default_debug_tty=/dev/tty666 systemd.debug_shell=yes"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/default.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service
grep -F "/dev/tty666" "$OUT_DIR/early/debug-shell.service.d/50-tty.conf"

# systemd.break (default)
: "debug-shell: regular + systemd.break"
CMDLINE="$CMDLINE systemd.break"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-udev.service"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-mount.service"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-switch-root.service"

# systemd.break=pre-switch-root
: "debug-shell: regular + systemd.break=pre-switch-root"
CMDLINE="$CMDLINE systemd.break=pre-switch-root"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-udev.service"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-mount.service"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-switch-root.service"

# systemd.break=pre-mount
: "debug-shell: regular + systemd.break=pre-mount"
CMDLINE="$CMDLINE systemd.break=pre-mount"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-udev.service"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-mount.service"
test ! -h "$OUT_DIR/early/default.target.wants/breakpoint-pre-switch-root.service"

# systemd.break=pre-basic
: "debug-shell: regular + systemd.break=pre-basic"
CMDLINE="$CMDLINE systemd.break=pre-basic"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/default.target.wants/breakpoint-pre-basic.service" /lib/systemd/system/breakpoint-pre-basic.service

# systemd.break=pre-udev
: "debug-shell: regular + systemd.break=pre-udev"
CMDLINE="$CMDLINE systemd.break=pre-udev"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/default.target.wants/breakpoint-pre-udev.service" /lib/systemd/system/breakpoint-pre-udev.service

# systemd.break=pre-udev,pre-basic,pre-mount,pre-switch-root
: "debug-shell: regular + systemd.break=pre-udev,pre-basic,pre-mount,pre-switch-root"
rm -f "$OUT_DIR/early/default.target.wants/breakpoint-pre-udev.service"
rm -f "$OUT_DIR/early/default.target.wants/breakpoint-pre-basic.service"
CMDLINE="$CMDLINE systemd.break=pre-udev,pre-basic,pre-mount,pre-switch-root"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/default.target.wants/breakpoint-pre-udev.service" /lib/systemd/system/breakpoint-pre-udev.service
link_endswith "$OUT_DIR/early/default.target.wants/breakpoint-pre-basic.service" /lib/systemd/system/breakpoint-pre-basic.service

# Now override the default target via systemd.unit=
: "debug-shell: regular + systemd.unit="
CMDLINE="$CMDLINE systemd.unit=my-fancy.target"
SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_eq "$OUT_DIR/early/masked-no-suffix.service" /dev/null
link_eq "$OUT_DIR/early/masked.service" /dev/null
link_eq "$OUT_DIR/early/masked.socket" /dev/null
link_endswith "$OUT_DIR/early/my-fancy.target.wants/wanted-no-suffix.service" /lib/systemd/system/wanted-no-suffix.service
link_endswith "$OUT_DIR/early/my-fancy.target.wants/wanted.service" /lib/systemd/system/wanted.service
link_endswith "$OUT_DIR/early/my-fancy.target.wants/wanted.mount" /lib/systemd/system/wanted.mount
link_endswith "$OUT_DIR/early/my-fancy.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service
test ! -d "$OUT_DIR/early/default.target.wants"


# Initrd scenario
: "debug-shell: initrd"
CMDLINE="ro root=/ ${ARGS[*]} systemd.debug_shell"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_eq "$OUT_DIR/early/masked-initrd.service" /dev/null
link_endswith "$OUT_DIR/early/initrd.target.wants/wanted-initrd.service" /lib/systemd/system/wanted-initrd.service
# The non-initrd stuff (i.e. without the rd. suffix) should be ignored in
# this case
test ! -h "$OUT_DIR/early/masked-no-suffix.service"
test ! -h "$OUT_DIR/early/masked.service"
test ! -h "$OUT_DIR/early/masked.socket"
test ! -h "$OUT_DIR/early/initrd.target.wants/debug-shell.service"
test ! -d "$OUT_DIR/early/default.target.wants"

# Again, but with rd.systemd.debug_shell
: "debug-shell: initrd + rd.systemd.debug_shell"
CMDLINE="$CMDLINE rd.systemd.debug_shell"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/initrd.target.wants/debug-shell.service" /lib/systemd/system/debug-shell.service

# rd.systemd.break (default)
: "debug-shell: initrd + rd.systemd.break"
CMDLINE="$CMDLINE rd.systemd.break"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-switch-root.service" /lib/systemd/system/breakpoint-pre-switch-root.service

# rd.systemd.break=pre-udev
: "debug-shell: initrd + rd.systemd.break=pre-udev"
CMDLINE="$CMDLINE rd.systemd.break=pre-udev"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-udev.service" /lib/systemd/system/breakpoint-pre-udev.service

# rd.systemd.break=pre-basic
: "debug-shell: initrd + rd.systemd.break=pre-basic"
CMDLINE="$CMDLINE rd.systemd.break=pre-basic"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-basic.service" /lib/systemd/system/breakpoint-pre-basic.service

# rd.systemd.break=pre-mount
: "debug-shell: initrd + rd.systemd.break=pre-mount"
CMDLINE="$CMDLINE rd.systemd.break=pre-mount"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-mount.service" /lib/systemd/system/breakpoint-pre-mount.service

# rd.systemd.break=pre-switch-root
: "debug-shell: initrd + rd.systemd.break=pre-switch-root"
rm -f "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-switch-root.service"
CMDLINE="$CMDLINE rd.systemd.break=pre-switch-root"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-switch-root.service" /lib/systemd/system/breakpoint-pre-switch-root.service

# rd.systemd.break=pre-udev,pre-basic,pre-mount,pre-switch-root
: "debug-shell: initrd + rd.systemd.break=pre-udev,pre-mount,pre-switch-root"
rm -f "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-udev.service"
rm -f "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-basic.service"
rm -f "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-mount.service"
rm -f "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-switch-root.service"
CMDLINE="$CMDLINE rd.systemd.break=pre-udev,pre-basic,pre-mount,pre-switch-root"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-udev.service" /lib/systemd/system/breakpoint-pre-udev.service
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-basic.service" /lib/systemd/system/breakpoint-pre-basic.service
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-mount.service" /lib/systemd/system/breakpoint-pre-mount.service
link_endswith "$OUT_DIR/early/initrd.target.wants/breakpoint-pre-switch-root.service" /lib/systemd/system/breakpoint-pre-switch-root.service

# Override the default target
: "debug-shell: initrd + rd.systemd.unit"
CMDLINE="$CMDLINE rd.systemd.unit=my-fancy-initrd.target"
SYSTEMD_IN_INITRD=1 SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
link_eq "$OUT_DIR/early/masked-initrd.service" /dev/null
link_endswith "$OUT_DIR/early/my-fancy-initrd.target.wants/wanted-initrd.service" /lib/systemd/system/wanted-initrd.service
test ! -d "$OUT_DIR/early/initrd.target.wants"
