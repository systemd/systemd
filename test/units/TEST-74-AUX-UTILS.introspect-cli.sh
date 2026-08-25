#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Some commands are in $PATH, others are in our private directories.
# Check the other locations too.
PATH=$PATH:/usr/lib/systemd:/usr/lib/udev

export SYSTEMD_PAGER=cat

# A smoke test for the introspection code
INTROSPECTABLE=(
    ata_id
    bootctl
    busctl
    cdrom_id
    coredumpctl
    dmi_memory_id
    fido_id
    halt
    homectl
    hostnamectl
    importctl
    iocost
    journalctl
    kernel-install
    localectl
    loginctl
    machinectl
    mtd_probe
    networkctl
    oomctl
    portablectl
    poweroff
    reboot
    resolvectl
    run0
    scsi_id
    shutdown
    storagectl
    systemctl
    systemd-ac-power
    systemd-analyze
    systemd-ask-password
    systemd-backlight
    systemd-battery-check
    systemd-binfmt
    systemd-bless-boot
    systemd-boot-check-no-failures
    systemd-bsod
    systemd-cat
    systemd-cgls
    systemd-cgtop
    systemd-clonesetup
    systemd-confext
    systemd-creds
    systemd-cryptenroll
    systemd-cryptsetup
    systemd-delta
    systemd-detect-virt
    systemd-dissect
    systemd-escape
    systemd-export
    systemd-factory-reset
    systemd-firstboot
    systemd-growfs
    systemd-hibernate-resume
    systemd-hwdb
    systemd-id128
    systemd-imds
    systemd-imdsd
    systemd-import
    systemd-import-fs
    systemd-inhibit
    systemd-integritysetup
    systemd-journal-gatewayd
    systemd-journal-remote
    systemd-journal-upload
    systemd-keyutil
    systemd-machine-id-setup
    systemd-measure
    systemd-modules-load
    systemd-mount
    systemd-mstack
    systemd-mute-console
    systemd-network-generator
    systemd-networkd-wait-online
    systemd-notify
    systemd-nspawn
    systemd-oomd
    systemd-path
    systemd-pcrextend
    systemd-pcrlock
    systemd-pty-forward
    systemd-pull
    systemd-random-seed
    systemd-repart
    systemd-report
    systemd-report-basic
    systemd-report-cgroup
    systemd-report-files
    systemd-report-sign-plain
    systemd-report-sign-tsm
    systemd-run
    systemd-sbsign
    systemd-sleep
    systemd-socket-activate
    systemd-socket-proxyd
    systemd-ssh-issue
    systemd-stdio-bridge
    systemd-storage-block
    systemd-storage-fs
    systemd-storagetm
    systemd-sysctl
    systemd-sysext
    systemd-sysinstall
    systemd-sysupdate
    systemd-sysusers
    systemd-tmpfiles
    systemd-tpm2-clear
    systemd-tpm2-setup
    systemd-tty-ask-password-agent
    systemd-umount
    systemd-update-done
    systemd-validatefs
    systemd-veritysetup
    systemd-vmspawn
    systemd-vpick
    timedatectl
    updatectl
    userdbctl
    v4l_id
    varlinkctl
)

for i in "${INTROSPECTABLE[@]}"; do
    command -v "$i" >/dev/null || continue

    $i --help >/dev/null

    $i --introspect-cli | jq -e \
        '.mediaType == "application/vnd.io.systemd.cli-introspection-0"'
    $i --introspect-cli | jq -e --arg name "$i" \
        'any(.commands[]; .names[0] == $name)'
    $i --introspect-cli | jq -e \
        'any(.commands[]; [.options[].names[-1]] | contains(["--help", "--version", "--introspect-cli"]))'
    $i --intro | grep -e --help

    # If the tool has a "help" verb, it must work too
    if $i --introspect-cli | jq -e --arg name "$i" \
            'any(.commands[]; any(.names[]; . == $name) and ((.verbs // []) | any(.names[0] == "help")))' \
             >/dev/null; then
        # 'systemctl help' shows unit manuals
        [[ "$i" == systemctl ]] && continue

        $i help >/dev/null
    fi
done

# check verbs and multicall binaries
if command -v systemd-hwdb >/dev/null; then
    systemd-hwdb --introspect-cli | jq -e \
            '.commands[0].verbs | map(.names[0]) | sort == ["help", "query", "update"]'
fi

if command -v kernel-install >/dev/null; then
    kernel-install --introspect-cli | jq -e \
            '[.commands[].names[0]] | sort == ["installkernel", "kernel-install"]'
fi

resolvectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["resolvconf", "resolvectl", "systemd-resolve"]'

storagectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.storage", "storagectl"]'

systemd-clonesetup --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | sort == ["add", "remove"]'

systemd-dissect --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.ddi", "systemd-dissect"]'

systemd-id128 --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | contains(["new", "machine-id", "show", "help"])'

if command -v systemd-mount >/dev/null; then
    systemd-mount --introspect-cli | jq -e \
        '[.commands[].names[0]] | sort == ["systemd-mount", "systemd-umount"]'

    # --tmpfs is only valid for systemd-mount
    (! systemd-mount --tmpfs 2>&1) | grep "one argument required" >/dev/null
    (! systemd-umount --tmpfs 2>&1) | grep "unrecognized option" >/dev/null
fi

systemd-mstack --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.mstack", "systemd-mstack"]'

systemd-run --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["run0", "systemd-run"]'

if command -v systemd-sysext >/dev/null; then
     systemd-sysext --introspect-cli | jq -e \
         '[.commands[].names[0]] | sort == ["systemd-confext", "systemd-sysext"]'

     systemd-sysext --introspect-cli | jq -e \
         '.commands[0].verbs | map(.names[0]) | contains(["status", "merge", "unmerge"])'
     systemd-confext --introspect-cli | jq -e \
         '.commands[0].verbs | map(.names[0]) | contains(["status", "merge", "unmerge"])'
fi

systemctl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["halt", "poweroff", "reboot", "shutdown", "systemctl"]'
