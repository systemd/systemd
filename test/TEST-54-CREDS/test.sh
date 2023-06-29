#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test credentials"

NSPAWN_CREDS=(
    "--set-credential=mynspawncredential:strangevalue"
)
NSPAWN_ARGUMENTS="${NSPAWN_ARGUMENTS:-} ${NSPAWN_CREDS[*]}"

QEMU_CREDS=(
    "-fw_cfg name=opt/io.systemd.credentials/myqemucredential,string=othervalue"
    "-smbios type=11,value=io.systemd.credential:smbioscredential=magicdata"
    "-smbios type=11,value=io.systemd.credential.binary:binarysmbioscredential=bWFnaWNiaW5hcnlkYXRh"
    "-smbios type=11,value=io.systemd.credential.binary:sysusers.extra=dSBjcmVkdGVzdHVzZXIK"
    "-smbios type=11,value=io.systemd.credential.binary:tmpfiles.extra=ZiAvdG1wL3NvdXJjZWRmcm9tY3JlZGVudGlhbCAtIC0gLSAtIHRtcGZpbGVzc2VjcmV0Cg=="
    "-smbios type=11,value=io.systemd.credential.binary:fstab.extra=aW5qZWN0ZWQgL2luamVjdGVkIHRtcGZzIFgtbW91bnQubWtkaXIgMCAwCg=="
    "-smbios type=11,value=io.systemd.credential:getty.ttys.container=idontexist"
)
QEMU_OPTIONS="${QEMU_OPTIONS:-} ${QEMU_CREDS[*]}"

KERNEL_CREDS=(
    "systemd.set_credential=kernelcmdlinecred:uff"
    "systemd.set_credential=sysctl.extra:kernel.domainname=sysctltest"
    "systemd.set_credential=login.motd:hello"
    "systemd.set_credential=login.issue:welcome"
    "rd.systemd.import_credentials=no"
)
KERNEL_APPEND="${KERNEL_APPEND:-} ${KERNEL_CREDS[*]}"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    instmods qemu_fw_cfg
    if get_bool "$LOOKS_LIKE_SUSE"; then
        instmods dmi-sysfs
    fi
    generate_module_dependencies
}

run_qemu_hook() {
    local td=/tmp/initrd.extra."$RANDOM"
    mkdir -m 755 "$td" "$td/etc" "$td"/etc/tmpfiles.d
    add_at_exit_handler "rm -rf $td"

    cat > "$td"/etc/tmpfiles.d/50-initrd-cred.conf <<EOF
d /run/credentials 0775
d /run/credentials/@initrd 0700
f /run/credentials/@initrd/myinitrdcred 0600 - - - guatemala
EOF

    ( cd "$td" && find . | cpio -o -c -R root:root > "$td".cpio )
    add_at_exit_handler "rm $td.cpio"

    INITRD_EXTRA="$td.cpio"
}

do_test "$@"
