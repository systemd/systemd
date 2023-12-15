#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test various scenarios involving transition from/to initrd"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"
    local sd_initrd file dir

    # Create a shutdown initrd
    #
    # This should provide coverage for shutdown initrd related issues, see:
    #   - https://github.com/systemd/systemd/issues/28645
    #   - https://github.com/systemd/systemd/pull/28648
    #   - https://github.com/systemd/systemd/pull/28793
    #
    # This is a bit messier than I originally anticipated, as installing our own libraries
    # is handled implicitly by install_systemd() which I don't want to use here, since
    # I need only the systemd-shutdown binary
    sd_initrd="$workspace/shutdown-initrd"
    mkdir -p "$sd_initrd/etc" "$sd_initrd/usr"
    initdir="$sd_initrd" image_install bash /usr/lib/os-release
    ln -srf "$sd_initrd/usr/lib/os-release" "$sd_initrd/etc/initrd-release"
    initdir="$sd_initrd" inst_binary "$workspace/usr/lib/systemd/systemd-shutdown" "/usr/lib/systemd/systemd-shutdown"
    initdir="$sd_initrd" inst_libs "$sd_initrd/usr/lib/systemd/systemd-shutdown"
    # We need to deal with libsystemd stuff explicitly, as we don't call install_systemd() here
    while read -r file; do
        initdir="$sd_initrd" inst_library "$file" "${file##"$workspace"}"
        initdir="$sd_initrd" inst_libs "$file"
    done < <(find "$workspace/usr/" -name "libsystemd*.so*")
    # Call systemd-shutdown indirectly, so we can show a message that we can check for
    # later to make sure the shutdown initrd was actually executed
    cat >"$sd_initrd/shutdown" <<\EOF
#!/usr/bin/bash -eu
echo "Hello from shutdown initrd"
exec /usr/lib/systemd/systemd-shutdown "$@"
EOF
    chmod +x "$sd_initrd/shutdown"
}

check_result_qemu_hook() {
    local workspace="${1:?}"
    local console_log="${TESTDIR:?}/console.log"

    if [[ -e "$workspace/skipped" ]]; then
        return 0
    fi

    if [[ ! -e "$console_log" ]]; then
        dfatal "Missing console log - this shouldn't happen"
        return 1
    fi

    # The console log should not contain messages like:
    # [    6.245000] systemd-shutdown[1]: Failed to move /run/initramfs to /: Invalid argument
    # [    6.245955] systemd-shutdown[1]: Failed to switch root to "/run/initramfs": Invalid argument
    if grep -qE "systemd-shutdown.+: Failed to move /run/initramfs" "$console_log" ||
       grep -qE "systemd-shutdown.+: Failed to switch root" "$console_log"; then
        derror "sd-shutdown failed to switch root in shutdown initrd"
        return 1
    fi

    # Check if the shutdown initrd was executed at all
    if ! grep -qE "^Hello from shutdown initrd\s*$" "$console_log"; then
        derror "Missing 'hello' message from shutdown initrd"
        return 1
    fi

    return 0
}

# Setup a one shot service in initrd that creates a dummy bind mount under /run
# to check if the mount persists though the initrd transition. The "check" part
# is in the respective testsuite-08.sh script.
#
# See: https://github.com/systemd/systemd/issues/28452
run_qemu_hook() {
    local extra="${TESTDIR:?}/initrd.extra"

    mkdir -m 755 "$extra"
    mkdir -m 755 "$extra/etc" "$extra/etc/systemd" "$extra/etc/systemd/system" "$extra/etc/systemd/system/initrd.target.wants"

    cat >"$extra/etc/systemd/system/initrd-run-mount.service" <<EOF
[Unit]
Description=Create a mount in /run that should survive the transition from initrd

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=mkdir /run/initrd-mount-source /run/initrd-mount-target
ExecStart=mount -v --bind /run/initrd-mount-source /run/initrd-mount-target
ExecStart=cp -v /etc/initrd-release /run/initrd-mount-target/hello-world
EOF
    ln -svrf "$extra/etc/systemd/system/initrd-run-mount.service" "$extra/etc/systemd/system/initrd.target.wants/initrd-run-mount.service"

    (cd "$extra" && find . | cpio -o -H newc -R root:root > "$extra.cpio")

    INITRD_EXTRA="$extra.cpio"
}

do_test "$@"
