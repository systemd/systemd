#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Some commands are in $PATH, others are in our private directories.
# Check the other locations too.
PATH=$PATH:/usr/lib/systemd:/usr/lib/systemd/system-generators:/usr/lib/systemd/user-generators:/usr/lib/systemd/user-environment-generators:/usr/lib/udev

export SYSTEMD_PAGER=cat

# --introspect-cli itself is marked as experimental
export SYSTEMD_EXPERIMENTAL=1

# Nope out if the build does not support experimental options at all
(! systemctl --introspect-cli) |& grep -F 'not supported' >/dev/null && exit 77

# Options and verbs (nested command objects) share the "arguments" array of a command object.
JQ_DEFS='def opts: [.arguments[]? | select(.type == "option")];
         def verbs: [.arguments[]? | select(.type == "command")];'

# Keys we emit which are defined by the spec. Everything else must carry the vendor prefix.
JQ_SPEC_KEYS='"mediaType", "commands", "type", "id", "names", "versions", "features", "project",
              "documentation", "abstract", "postscript", "help", "synopsis", "arguments",
              "value", "valueName", "sections", "isDeprecated", "isExperimental"'

# A smoke test for the introspection code
INTROSPECTABLE=(
    30-systemd-environment-d-generator
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
    ptyctl
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
    systemd-bless-boot-generator
    systemd-boot-check-no-failures
    systemd-bsod
    systemd-cat
    systemd-cgls
    systemd-cgtop
    systemd-clonesetup
    systemd-clonesetup-generator
    systemd-confext
    systemd-creds
    systemd-cryptenroll
    systemd-cryptsetup
    systemd-cryptsetup-generator
    systemd-debug-generator
    systemd-delta
    systemd-detect-virt
    systemd-dissect
    systemd-escape
    systemd-executor
    systemd-export
    systemd-factory-reset
    systemd-factory-reset-generator
    systemd-firstboot
    systemd-fstab-generator
    systemd-getty-generator
    systemd-gpt-auto-generator
    systemd-growfs
    systemd-hibernate-resume
    systemd-hibernate-resume-generator
    systemd-homed
    systemd-hostnamed
    systemd-hwdb
    systemd-id128
    systemd-imds
    systemd-imds-generator
    systemd-imdsd
    systemd-import
    systemd-import-fs
    systemd-import-generator
    systemd-importd
    systemd-inhibit
    systemd-integritysetup
    systemd-integritysetup-generator
    systemd-journal-gatewayd
    systemd-journal-remote
    systemd-journal-upload
    systemd-journald
    systemd-keyutil
    systemd-localed
    systemd-logind
    systemd-machine-id-setup
    systemd-machined
    systemd-measure
    systemd-modules-load
    systemd-mount
    systemd-mountfsd
    systemd-mstack
    systemd-mute-console
    systemd-network-generator
    systemd-networkd
    systemd-networkd-wait-online
    systemd-notify
    systemd-nspawn
    systemd-nsresourced
    systemd-oomd
    systemd-path
    systemd-pcrextend
    systemd-pcrlock
    systemd-portabled
    systemd-pty-forward
    systemd-pull
    systemd-random-seed
    systemd-remount-fs
    systemd-repart
    systemd-report
    systemd-report-basic
    systemd-report-cgroup
    systemd-report-diskhealth
    systemd-report-diskspace
    systemd-report-files
    systemd-report-hwmon
    systemd-report-netstat
    systemd-report-sign-plain
    systemd-report-sign-tpm2
    systemd-report-sign-tsm
    systemd-resolved
    systemd-rfkill
    systemd-run
    systemd-run-generator
    systemd-sbsign
    systemd-shutdown
    systemd-sleep
    systemd-socket-activate
    systemd-socket-proxyd
    systemd-ssh-generator
    systemd-ssh-issue
    systemd-stdio-bridge
    systemd-storage-block
    systemd-storage-fs
    systemd-storagetm
    systemd-sysctl
    systemd-sysext
    systemd-sysinstall
    systemd-sysroot-fstab-check
    systemd-system-update-generator
    systemd-sysupdate
    systemd-sysupdated
    systemd-sysusers
    systemd-time-wait-sync
    systemd-timedated
    systemd-timesyncd
    systemd-tmpfiles
    systemd-tpm2-clear
    systemd-tpm2-generator
    systemd-tpm2-setup
    systemd-tpm2-swtpm
    systemd-tty-ask-password-agent
    systemd-udevd
    systemd-umount
    systemd-update-done
    systemd-update-helper
    systemd-userdbd
    systemd-validatefs
    systemd-veritysetup
    systemd-veritysetup-generator
    systemd-vmspawn
    systemd-vpick
    systemd-xdg-autostart-generator
    timedatectl
    udevadm
    updatectl
    userdbctl
    v4l_id
    varlinkctl
)

for i in "${INTROSPECTABLE[@]}"; do
    command -v "$i" >/dev/null || continue

    $i --introspect-cli | jq -e \
        '.mediaType == "application/vnd.uapi-group.cli-introspection"'
    $i --introspect-cli | jq -e --arg name "$i" \
        'any(.commands[]; .names[0] == $name)'
    $i --introspect-cli | jq -e \
        'all(.commands[]; .type == "command" and .id == .names[0] and (.versions | type == "array") and
                          all(.arguments[]?;
                              (.type == "command" and .id == .names[0]) or
                              (.type == "option" and .id == (.names[-1] | ltrimstr("--") | ltrimstr("-")))))'
    $i --introspect-cli | jq -e \
        '[.. | objects | keys[]] | all(IN('"$JQ_SPEC_KEYS"') or startswith("x-systemd."))'
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

networkctl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["networkctl", "systemd-networkd"]'

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
# options carry the name of their value and their section, commands list their man pages
# and their synopsis lines, one array per line. Our extensions carry the "x-systemd." prefix.
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "new") |
        .help == "Generate a new ID" and .sections == ["Commands"]'
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | opts[] | select(.names[-1] == "--json") |
        .id == "json" and .value == "yes" and .valueName == "FORMAT" and .sections == ["Options"]'
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | opts[] | select(.names[-1] == "-j") |
        .id == "j" and .value == "no" and (has("valueName") | not)'
systemd-id128 --introspect-cli | jq -e \
    '.commands[0].documentation == ["man:systemd-id128(1)"]'
systemd-id128 --introspect-cli | jq -e \
    '.commands[0] | has("isExperimental") | not'

# Commands marked as experimental say so
for i in systemd-measure systemd-pcrlock systemd-report systemd-sysupdate systemd-vmspawn; do
    command -v "$i" >/dev/null || continue
    $i --introspect-cli | jq -e --arg name "$i" \
        'any(.commands[]; .names[0] == $name and .isExperimental == true)'
done
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "show") | .synopsis == [["[NAME|UUID]"]]'
systemd-id128 --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "new") |
        (has("synopsis") | not) and ."x-systemd.maxArguments" == 1'

if command -v systemd-analyze >/dev/null; then
    systemd-analyze --introspect-cli | jq -e "$JQ_DEFS"'
        .commands[0] | verbs[] | select(.names[0] == "time") | .sections == ["Boot Analysis"]'
fi

if command -v systemd-nspawn >/dev/null; then
    systemd-nspawn --introspect-cli | jq -e \
        '.commands[0].synopsis == [["[PATH] [ARGUMENTS…]"]]'
fi

# udevadm's verbs carry their own options, reported recursively
udevadm --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] | select(.names[0] == "info") |
        [opts[].names[-1]] | contains(["--query", "--json", "--no-pager"])'

udevadm --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] |
        select(.names[0] == "hwdb") | .isDeprecated == true'

# udevadm lock has multiple argspecs. Check that we print them.
udevadm lock -h | grep -E '^> udevadm .* lock .* COMMAND$'
udevadm lock -h | grep -E '^> udevadm .* lock .* --print$'
udevadm --introspect-cli | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] | select(.names[0] == "lock") |
        .synopsis == [["COMMAND"], ["--print"]]'

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
        '.mediaType == "application/vnd.uapi-group.cli-introspection"'
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
