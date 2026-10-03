#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Some commands are in $PATH, others are in our private directories.
# Check the other locations too.
PATH=$PATH:/usr/lib/systemd:/usr/lib/udev

export SYSTEMD_PAGER=cat

# Options and verbs (nested command objects) share the "arguments" array of a command object.
JQ_DEFS='def opts: [.arguments[]? | select(.type == "option")];
         def verbs: [.arguments[]? | select(.type == "command")];'

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
    systemd
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
    systemd-executor
    systemd-export
    systemd-factory-reset
    systemd-firstboot
    systemd-growfs
    systemd-hibernate-resume
    systemd-homed
    systemd-hostnamed
    systemd-hwdb
    systemd-id128
    systemd-imds
    systemd-imdsd
    systemd-import
    systemd-import-fs
    systemd-importd
    systemd-inhibit
    systemd-integritysetup
    systemd-journal-gatewayd
    systemd-journal-remote
    systemd-journal-upload
    systemd-keyutil
    systemd-localed
    systemd-logind
    systemd-machine-id-setup
    systemd-machined
    systemd-measure
    systemd-modules-load
    systemd-mount
    systemd-mstack
    systemd-mute-console
    systemd-network-generator
    systemd-networkd
    systemd-networkd-wait-online
    systemd-notify
    systemd-nspawn
    systemd-oomd
    systemd-path
    systemd-pcrextend
    systemd-pcrlock
    systemd-portabled
    systemd-pty-forward
    systemd-pull
    systemd-random-seed
    systemd-repart
    systemd-report
    systemd-report-basic
    systemd-report-cgroup
    systemd-report-diskspace
    systemd-report-files
    systemd-report-hwmon
    systemd-report-sign-plain
    systemd-report-sign-tpm2
    systemd-report-sign-tsm
    systemd-resolved
    systemd-run
    systemd-sbsign
    systemd-shutdown
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
    systemd-sysupdated
    systemd-sysusers
    systemd-timedated
    systemd-timesyncd
    systemd-tmpfiles
    systemd-tpm2-clear
    systemd-tpm2-setup
    systemd-tty-ask-password-agent
    systemd-udevd
    systemd-umount
    systemd-update-done
    systemd-validatefs
    systemd-veritysetup
    systemd-vmspawn
    systemd-vpick
    timedatectl
    udevadm
    updatectl
    userdbctl
    v4l_id
    varlinkctl
)

for i in "${INTROSPECTABLE[@]}"; do
    command -v "$i" >/dev/null || continue

    help="$($i --help)"
    (! grep -E '^See the [^[:space:]]+\.[[:alnum:]]+ man page for details\.$' <<<"$help" >/dev/null)

    $i --introspect-cli | jq -e \
        '.mediaType == "application/vnd.io.systemd.cli-introspection-0"'
    $i --introspect-cli | jq -e --arg name "$i" \
        'any(.commands[]; .names[0] == $name)'
    $i --introspect-cli | jq -e \
        'all(.commands[]; .type == "command" and (.version | type == "array") and
                          all(.arguments[]?; .type == "option" or .type == "command"))'
    $i --introspect-cli | jq -e "$JQ_DEFS"'
        any(.commands[]; [opts[].names[-1]] | contains(["--help", "--version", "--introspect-cli"]))'
    $i --intro | grep -e --help

    # If the tool has a "help" verb, it must work too
    if $i --introspect-cli | jq -e --arg name "$i" "$JQ_DEFS"'
            any(.commands[]; any(.names[]; . == $name) and (verbs | any(.names[0] == "help")))' \
             >/dev/null; then
        # 'systemctl help' shows unit manuals
        [[ "$i" == systemctl ]] && continue

        $i help >/dev/null
    fi
done

# check verbs and multicall binaries
if command -v systemd-hwdb >/dev/null; then
    systemd-hwdb --introspect-cli | jq -e "$JQ_DEFS"'
            .commands[0] | verbs | map(.names[0]) | sort == ["help", "query", "update"]'
fi

if command -v kernel-install >/dev/null; then
    kernel-install --introspect-cli | jq -e \
            '[.commands[].names[0]] | sort == ["installkernel", "kernel-install"]'
fi

resolvectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["resolvconf", "resolvectl", "systemd-resolve"]'

storagectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.storage", "storagectl"]'

systemd-clonesetup --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | verbs | map(.names[0]) | sort == ["add", "remove"]'

systemd-dissect --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.ddi", "systemd-dissect"]'

# systemd-hostnamed does not support --system/--user: options from groups not listed by the
# command must be rejected as unknown and hidden from the introspection (option group filtering)
if command -v systemd-hostnamed >/dev/null; then
    (! systemd-hostnamed --system 2>&1) | grep "unrecognized option" >/dev/null
    systemd-hostnamed --introspect-cli | jq -e "$JQ_DEFS"'
        all(.commands[]; all(opts[]; .names[-1] != "--system"))'
fi

systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | verbs | map(.names[0]) | contains(["new", "machine-id", "show", "help"])'

# Details of the schema: verbs carry a one-line help and the section they are listed under,
# options carry the name of their argument and their section, commands list their man pages
# and (as an extension) the raw synopsis lines.
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "new") |
        .help == "Generate a new ID" and .sections == ["Commands"]'
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | opts[] | select(.names[-1] == "--json") |
        .argument == "required_argument" and .value_name == "FORMAT" and .sections == ["Options"]'
systemd-id128 --introspect-cli | jq -e \
    '.commands[0].documentation == ["man:systemd-id128(1)"]'
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "show") | .synopsis == ["[NAME|UUID]"]'

if command -v systemd-analyze >/dev/null; then
    systemd-analyze --introspect-cli | jq -e "$JQ_DEFS"'
        .commands[0] | verbs[] | select(.names[0] == "time") | .sections == ["Boot Analysis"]'
fi

if command -v systemd-nspawn >/dev/null; then
    systemd-nspawn --introspect-cli | jq -e \
        '.commands[0].synopsis == ["[PATH] [ARGUMENTS…]"]'
fi

# udevadm's verbs carry their own options, reported recursively
udevadm --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] | select(.names[0] == "info") |
        [opts[].names[-1]] | contains(["--query", "--json", "--no-pager"])'

udevadm --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] |
        select(.names[0] == "hwdb") | .isDeprecated == true'

# udevadm print has multiple argspecs. Check that we print them.
udevadm lock -h | grep -E '^> udevadm .* lock .* COMMAND$'
udevadm lock -h | grep -E '^> udevadm .* lock .* --print$'

# udevadm is also systemd-udevd
udevadm --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["systemd-udevd", "udevadm"]'

# The systemd-udevd command must own no verbs: the help-verb check in the loop above relies on
# this to never run 'systemd-udevd help', which would start the daemon.
udevadm --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "systemd-udevd") | verbs == []'

# Each subcommand's help and introspection must work
for v in cat control hwdb info lock monitor settle test test-builtin trigger verify wait; do
    udevadm "$v" --help >/dev/null
    udevadm "$v" --introspect-cli | jq -e \
        '.mediaType == "application/vnd.io.systemd.cli-introspection-0"'
done

# systemd is optionally a multicall binary that also provides systemd-executor
if [[ "$(readlink "$(command -v systemd-executor)" 2>/dev/null)" == systemd ]]; then
    systemd --introspect-cli | jq -e \
        '[.commands[].names[0]] | sort == ["systemd", "systemd-executor"]'
fi

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

     systemd-sysext --introspect-cli | jq -e "$JQ_DEFS"'
         .commands[0] | verbs | map(.names[0]) | contains(["status", "merge", "unmerge"])'
     systemd-confext --introspect-cli | jq -e "$JQ_DEFS"'
         .commands[0] | verbs | map(.names[0]) | contains(["status", "merge", "unmerge"])'
fi

systemctl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["halt", "poweroff", "reboot", "shutdown", "systemctl"]'
