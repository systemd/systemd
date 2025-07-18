#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail
# Disable history expansion so we don't have to escape ! in strings below
set +o histexpand

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-getty-generator"
OUT_DIR="$(mktemp -d /tmp/getty-generator.XXX)"

at_exit() {
    rm -frv "${OUT_DIR:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

check_none() {
    [[ "$(find "$OUT_DIR" ! -type d | wc -l)" -eq 0 ]]
}

check_container() {
    link_endswith "$OUT_DIR/normal/getty.target.wants/console-getty.service" "/lib/systemd/system/console-getty.service"
    link_endswith "$OUT_DIR/normal/getty.target.wants/container-getty@0.service" "/lib/systemd/system/container-getty@.service"
    test ! -e "$OUT_DIR/normal/getty.target.wants/container-getty@tty0.service"
    test ! -h "$OUT_DIR/normal/getty.target.wants/container-getty@tty0.service"
}

check_no_container() {
    local unit

    for unit in console-getty.service container-getty@0.service container-getty@tty0.service; do
        test ! -e "$OUT_DIR/normal/getty.target.wants/$unit"
        test ! -h "$OUT_DIR/normal/getty.target.wants/$unit"
    done
}

DUMMY_ACTIVE_CONSOLES=(
    "hvc99"
    "xvc99"
    "hvsi99"
    "sclp_line99"
    "ttysclp99"
    "3270!tty99"
    "dummy99"
)
DUMMY_INACTIVE_CONSOLES=(
    "inactive99"
    "xvc199"
)
DUMMY_CONSOLES=(
    "${DUMMY_ACTIVE_CONSOLES[@]}"
    "${DUMMY_INACTIVE_CONSOLES[@]}"
)

check_console() {
    local console unit

    for console in "${DUMMY_ACTIVE_CONSOLES[@]}"; do
        unit="$(systemd-escape --template serial-getty@.service "$console")"
        link_endswith "$OUT_DIR/normal/getty.target.wants/$unit" "/lib/systemd/system/serial-getty@.service"
    done
    for console in "${DUMMY_INACTIVE_CONSOLES[@]}" /dev/notatty99; do
        unit="$(systemd-escape --template serial-getty@.service "$console")"
        test ! -e "$OUT_DIR/normal/getty.target.wants/$unit"
        test ! -h "$OUT_DIR/normal/getty.target.wants/$unit"
    done
}

check_no_console() {
    local console unit

    for console in "${DUMMY_CONSOLES[@]}" /dev/notatty99; do
        unit="$(systemd-escape --template serial-getty@.service "$console")"
        test ! -e "$OUT_DIR/normal/getty.target.wants/$unit"
        test ! -h "$OUT_DIR/normal/getty.target.wants/$unit"
    done
}

BUILTINS=(
    "hvc0"
    "xvc0"
    "hvsi0"
    "sclp_line0"
    "ttysclp0"
    "3270/tty1"
)

check_builtin() {
    local console unit

    for console in "${BUILTINS[@]}"; do
        unit="$(systemd-escape --template serial-getty@.service "$console")"
        if [[ -e "/dev/$console" ]]; then
            link_endswith "$OUT_DIR/normal/getty.target.wants/$unit" "/lib/systemd/system/serial-getty@.service"
        else
            test ! -e "$OUT_DIR/normal/getty.target.wants/$unit"
            test ! -h "$OUT_DIR/normal/getty.target.wants/$unit"
        fi
    done
}

check_no_builtin() {
    local console unit

    for console in "${BUILTINS[@]}"; do
        unit="$(systemd-escape --template serial-getty@.service "$console")"
        test ! -e "$OUT_DIR/normal/getty.target.wants/$unit"
        test ! -h "$OUT_DIR/normal/getty.target.wants/$unit"
    done
}

if in_container; then
    # Do a limited test in a container, as writing to /dev is usually restrited
    : "getty-generator: \$container_ttys env (container)"
    # In a container we allow only /dev/pts/* ptys
    PID1_ENVIRON="container_ttys=tty0 pts/0 /dev/tty0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
    check_container
    check_no_console
    check_no_builtin

    : "getty-generator: SYSTEMD_GETTY_AUTO=0 in PID1's environment (container)"
    PID1_ENVIRON="container_ttys=tty0 pts/0 /dev/tty0\0SYSTEMD_GETTY_AUTO=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
    check_none

    : "getty-generator: SYSTEMD_GETTY_AUTO=console in PID1's environment (container)"
    PID1_ENVIRON="container_ttys=tty0 pts/0 /dev/tty0\0SYSTEMD_GETTY_AUTO=console" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
    check_none

    : "getty-generator: SYSTEMD_GETTY_AUTO=console,builtin in PID1's environment (container)"
    PID1_ENVIRON="container_ttys=tty0 pts/0 /dev/tty0\0SYSTEMD_GETTY_AUTO=console,builtin" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
    check_none

    : "getty-generator: SYSTEMD_GETTY_AUTO=console,builtin,container in PID1's environment (container)"
    PID1_ENVIRON="container_ttys=tty0 pts/0 /dev/tty0\0SYSTEMD_GETTY_AUTO=console,builtin,container" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
    check_container
    check_no_console
    check_no_builtin

    exit 0
fi

# Create a bunch of dummy consoles
for console in "${DUMMY_CONSOLES[@]}"; do
    mknod "/dev/$console" c 4 0
done
# Sneak in one "not-a-tty" console
touch /dev/notatty99
# Temporarily replace /sys/class/tty/console/active with our list of dummy
# consoles so getty-generator can process them
echo -ne "${DUMMY_ACTIVE_CONSOLES[@]}" /dev/notatty99 >/tmp/dummy-active-consoles
mount -v --bind /tmp/dummy-active-consoles /sys/class/tty/console/active

: "getty-generator: no arguments"
# Sneak in an invalid value for $SYSTEMD_GETTY_AUTO to test things out
PID1_ENVIRON="SYSTEMD_GETTY_AUTO=foo" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_no_container
check_console
check_builtin

: "getty-generator: systemd.getty_auto=0 on kernel cmdline"
SYSTEMD_PROC_CMDLINE="systemd.getty_auto=foo systemd.getty_auto=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_none

: "getty-generator: systemd.getty_auto=container on kernel cmdline"
SYSTEMD_PROC_CMDLINE="systemd.getty_auto=foo systemd.getty_auto=container" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_none

: "getty-generator: systemd.getty_auto=container,console on kernel cmdline"
SYSTEMD_PROC_CMDLINE="systemd.getty_auto=foo systemd.getty_auto=container,console" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_no_container
check_console
check_no_builtin

: "getty-generator: systemd.getty_auto=container,builtin on kernel cmdline"
SYSTEMD_PROC_CMDLINE="systemd.getty_auto=foo systemd.getty_auto=container,builtin" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_no_container
check_no_console
check_builtin

: "getty-generator: SYSTEMD_GETTY_AUTO=0 in PID1's environment"
PID1_ENVIRON="SYSTEMD_GETTY_AUTO=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_none

: "getty-generator: SYSTEMD_GETTY_AUTO=container in PID1's environment"
PID1_ENVIRON="SYSTEMD_GETTY_AUTO=container" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_none

: "getty-generator: SYSTEMD_GETTY_AUTO=container,console in PID1's environment"
PID1_ENVIRON="SYSTEMD_GETTY_AUTO=container,console" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_no_container
check_console
check_no_builtin

: "getty-generator: SYSTEMD_GETTY_AUTO=container,builtin in PID1's environment"
PID1_ENVIRON="SYSTEMD_GETTY_AUTO=container,builtin" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_no_container
check_no_console
check_builtin

# Cleanup
umount /sys/class/tty/console/active --lazy
rm -f "${DUMMY_CONSOLES[@]/#//dev/}" /dev/notatty99
