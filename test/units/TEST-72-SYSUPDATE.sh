#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

SYSUPDATE=/usr/bin/systemd-sysupdate
SYSUPDATED=/lib/systemd/systemd-sysupdated
UPDATECTL=""
VARLINK_SOCKET=/run/systemd/io.systemd.SysUpdate
SECTOR_SIZES=(512 4096)
WORKDIR="$(mktemp -d /var/tmp/test-72-XXXXXX)"
CONFIGDIR="/run/sysupdate.d"
BACKING_FILE="$WORKDIR/joined.raw"
export SYSTEMD_ESP_PATH="$WORKDIR/esp"
export SYSTEMD_XBOOTLDR_PATH="$WORKDIR/xbootldr"
export SYSTEMD_PAGER=cat
export SYSTEMD_LOG_LEVEL=debug

if [[ ! -x "$SYSUPDATE" ]]; then
    echo "no systemd-sysupdate" >/skipped
    exit 77
fi

if [[ -x "$SYSUPDATED" ]]; then
    UPDATECTL="$(command -v updatectl || true)"
fi

# Loopback devices may not be supported. They are used because sfdisk cannot
# change the sector size of a file, and we want to test both 512 and 4096 byte
# sectors. If loopback devices are not supported, we can only test one sector
# size, and the underlying device is likely to have a sector size of 512 bytes.
if [[ ! -e /dev/loop-control ]]; then
    echo "No loopback device support"
    SECTOR_SIZES=(512)
fi

# Set up sysupdated and varlink drop-ins pointing at the correct definitions and
# setting no verification of images.
mkdir -p /run/systemd/system/systemd-sysupdated.service.d
cat >/run/systemd/system/systemd-sysupdated.service.d/override.conf<<EOF
[Service]
Environment=SYSTEMD_SYSUPDATE_NO_VERIFY=1
Environment=SYSTEMD_ESP_PATH=${SYSTEMD_ESP_PATH}
Environment=SYSTEMD_XBOOTLDR_PATH=${SYSTEMD_XBOOTLDR_PATH}
EOF

mkdir -p /run/systemd/system/systemd-sysupdate@.service.d
cat >/run/systemd/system/systemd-sysupdate@.service.d/override.conf<<EOF
[Service]
Environment=SYSTEMD_SYSUPDATE_NO_VERIFY=1
Environment=SYSTEMD_ESP_PATH=${SYSTEMD_ESP_PATH}
Environment=SYSTEMD_XBOOTLDR_PATH=${SYSTEMD_XBOOTLDR_PATH}
EOF

systemctl daemon-reload

SIGTEST_GPGHOME=
SIGTEST_OTHERHOME=

at_exit() {
    set +e

    systemctl stop test-sysupdate-notify-recorder.socket
    rm -f /run/systemd/system/test-sysupdate-notify-recorder.socket \
          /run/systemd/system/test-sysupdate-notify-recorder@.service

    losetup -n --output NAME --associated "$BACKING_FILE" | while read -r loop_dev; do
        losetup --detach "$loop_dev"
    done

    if [ "$SIGTEST_GPGHOME" != "" ]; then
        gpgconf --homedir "$SIGTEST_GPGHOME" --kill all 2>/dev/null
    fi
    if [ "$SIGTEST_OTHERHOME" != "" ]; then
        gpgconf --homedir "$SIGTEST_OTHERHOME" --kill all 2>/dev/null
    fi

    rm -rf "$WORKDIR"
}

trap at_exit EXIT

update_checksums() {
    (cd "$WORKDIR/source" && rm -f BEST-BEFORE-* && sha256sum uki* part* dir-*.tar.gz linux* >SHA256SUMS)
}

update_checksums_with_best_before() {
    (cd "$WORKDIR/source" && rm -f BEST-BEFORE-* && touch "BEST-BEFORE-$1" && sha256sum uki* part* dir-*.tar.gz linux* "BEST-BEFORE-$1" >SHA256SUMS)
}

new_version() {
    local sector_size="${1:?}"
    local version="${2:?}"
    local corrupt="${3:-}"

    # Create a pair of random partition payloads, and compress one.
    # To make not the initial bytes of part1-xxx.raw accidentally match one of the compression header,
    # let's make the first sector filled by zero.
    dd if=/dev/zero of="$WORKDIR/source/part1-$version.raw" bs="$sector_size" count=1
    dd if=/dev/urandom of="$WORKDIR/source/part1-$version.raw" bs="$sector_size" count=2047 conv=notrunc oflag=append
    dd if=/dev/urandom of="$WORKDIR/source/part2-$version.raw" bs="$sector_size" count=2048
    gzip -k -f "$WORKDIR/source/part2-$version.raw"

    # Create a file payload and a suffixed version
    echo $RANDOM >"$WORKDIR/source/linux-$version.erofs"
    echo $RANDOM >"$WORKDIR/source/linux-$version.erofs.caibx"

    # Create a random "UKI" payload
    echo $RANDOM >"$WORKDIR/source/uki-$version.efi"

    # Create a random extra payload
    echo $RANDOM >"$WORKDIR/source/uki-extra-$version.efi"

    # Create a random optional payload
    echo $RANDOM >"$WORKDIR/source/optional-$version.efi"

    # Create tarball of a directory
    mkdir -p "$WORKDIR/source/dir-$version"
    echo $RANDOM >"$WORKDIR/source/dir-$version/foo.txt"
    echo $RANDOM >"$WORKDIR/source/dir-$version/bar.txt"
    tar --numeric-owner -C "$WORKDIR/source/dir-$version/" -czf "$WORKDIR/source/dir-$version.tar.gz" .

    if [[ "$corrupt" == "corrupt-checksum" ]]; then
        # As requested, add a deliberately corrupt checksum for this file. This
        # will get overwritten next time update_checksums() is called, but the
        # integration test will probably have moved on to other things by then.
        {
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  part1-$version.raw"
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  part2-$version.raw"
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  part2-$version.raw.gz"
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  linux-$version.erofs"
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  linux-$version.erofs.caibx"
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  uki-$version.efi"
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  uki-extra-$version.efi"
            echo "abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea  dir-$version.tar.gz"
        } >> "$WORKDIR/source/SHA256SUMS"
    else
        update_checksums
    fi
}

check_no_new_update_available() {
    local client="${1:?}"

    if [[ "$client" == "sysupdate-cli" ]]; then
        (! "$SYSUPDATE" --verify=no check-new)
    elif [[ "$client" == "varlink" ]]; then
        (! varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.CheckNew '{"target":{"class":"host"}}') |& grep io.systemd.SysUpdate.NoUpdateNeeded >/dev/null
    else
        exit 1
    fi
}

check_new_update_available() {
    local client="${1:?}"

    if [[ "$client" == "sysupdate-cli" ]]; then
        "$SYSUPDATE" --verify=no check-new
    elif [[ "$client" == "varlink" ]]; then
        varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.CheckNew '{"target":{"class":"host"}}' | grep available
    else
        exit 1
    fi
}

update_now() {
    local update_type="${1:?}"
    local client="${2:?}"
    local checks="${3:-}"

    # Update to newest version. First there should be an update ready, then we
    # do the update, and then there should not be any ready anymore
    #
    # The update can either be done monolithically (by calling the `update`
    # verb) or split (`acquire` then `update`). Both options are allowed for
    # most updates in the test suite, so the test suite can be run to test both
    # modes. Some updates in the test suite need to be monolithic (e.g. when
    # repairing an installation), so that can be overridden via the local.

    if [[ "$checks" != "no-checks" ]]; then
        check_new_update_available "$client"
    fi

    if [[ "$update_type" == "monolithic" ]]; then
        "$SYSUPDATE" --verify=no update
    elif [[ "$update_type" == "split-offline" ]]; then
        "$SYSUPDATE" --verify=no acquire
        "$SYSUPDATE" --verify=no update --offline
    elif [[ "$update_type" == "split" ]]; then
        "$SYSUPDATE" --verify=no acquire
        "$SYSUPDATE" --verify=no update
    elif [[ "$update_type" == "updatectl" ]]; then
        if [[ -x "$UPDATECTL" ]]; then
            systemctl start systemd-sysupdated
            "$UPDATECTL" update
        else
            # Gracefully fall back to sysupdate
            "$SYSUPDATE" --verify=no update
        fi
    else
        exit 1
    fi

    if [[ "$checks" != "no-checks" ]]; then
        check_no_new_update_available "$client"
    fi
}

verify_version() {
    local block_device="${1:?}"
    local sector_size="${2:?}"
    local version="${3:?}"
    local part1_number="${4:?}"
    local gpt_reserved_sectors part2_number part1_offset part2_offset

    part2_number=$(( part1_number + 2 ))
    gpt_reserved_sectors=$((1024 * 1024 / sector_size))
    part1_offset=$(((part1_number - 1) * 2048 + gpt_reserved_sectors))
    part2_offset=$(((part2_number - 1) * 2048 + gpt_reserved_sectors))

    # Check the partitions
    dd if="$block_device" bs="$sector_size" skip="$part1_offset" count=2048 | cmp "$WORKDIR/source/part1-$version.raw"
    dd if="$block_device" bs="$sector_size" skip="$part2_offset" count=2048 | cmp "$WORKDIR/source/part2-$version.raw"

    # Check the UKI
    cmp "$WORKDIR/source/uki-$version.efi" "$WORKDIR/xbootldr/EFI/Linux/uki_$version+3-0.efi"
    test -z "$(ls -A "$WORKDIR/esp/EFI/Linux")"

    # Check the extra efi
    cmp "$WORKDIR/source/uki-extra-$version.efi" "$WORKDIR/xbootldr/EFI/Linux/uki_$version.efi.extra.d/extra.addon.efi"

    # Check the regular file and its suffixed version
    cmp "$WORKDIR/source/linux-$version.erofs" "$WORKDIR/system/linux-$version.erofs"
    cmp "$WORKDIR/source/linux-$version.erofs.caibx" "$WORKDIR/system/linux-$version.erofs.caibx"
}

verify_version_current() {
    local version="${3:?}"

    verify_version "$@"

    # Check the directories
    cmp "$WORKDIR/source/dir-$version/foo.txt" "$WORKDIR/dirs/current/foo.txt"
    cmp "$WORKDIR/source/dir-$version/bar.txt" "$WORKDIR/dirs/current/bar.txt"
}

verify_object_fields() {
    local updatectl_output="${1:?}"

    [[ "${updatectl_output}" != *"Unrecognized object field"* ]]
}

for sector_size in "${SECTOR_SIZES[@]}"; do
for client in sysupdate-cli varlink; do
for update_type in monolithic split-offline split updatectl; do
    # Disk size of:
    # - 1MB for GPT
    # - 4 partitions of 2048 sectors each
    # - 1MB for backup GPT
    disk_size=$((sector_size * 2048 * 4 + 1024 * 1024 * 2))
    rm -f "$BACKING_FILE"
    truncate -s "$disk_size" "$BACKING_FILE"

    if [[ -e /dev/loop-control ]]; then
        blockdev="$(losetup --find --show --sector-size "$sector_size" "$BACKING_FILE")"
    else
        blockdev="$BACKING_FILE"
    fi

    sfdisk "$blockdev" <<EOF
label: gpt
unit: sectors
sector-size: $sector_size

size=2048, type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, name=_empty
size=2048, type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, name=_empty
size=2048, type=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5, name=_empty
size=2048, type=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5, name=_empty
EOF

    for d in "$WORKDIR/dirs" "$CONFIGDIR"; do
        rm -rf "$d"
        mkdir -p "$d"
    done

    cat >"$CONFIGDIR/01-first.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=part1-@v.raw

[Target]
Type=partition
Path=$blockdev
MatchPattern=part1-@v
MatchPartitionType=root-x86-64
EOF

    cat >"$CONFIGDIR/02-second.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=part2-@v.raw.gz

[Target]
Type=partition
Path=$blockdev
MatchPattern=a-very-long-partition-name-@v
MatchPartitionType=root-x86-64-verity
EOF

    cat >"$CONFIGDIR/03-third.transfer" <<EOF
[Source]
Type=directory
Path=$WORKDIR/source
MatchPattern=dir-@v

[Target]
Type=directory
Path=$WORKDIR/dirs
CurrentSymlink=$WORKDIR/dirs/current
MatchPattern=dir-@v
InstancesMax=3
EOF

    cat >"$CONFIGDIR/04-fourth.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=uki-@v.efi

[Target]
Type=regular-file
Path=/EFI/Linux
PathRelativeTo=boot
MatchPattern=uki_@v+@l-@d.efi \
            uki_@v+@l.efi \
            uki_@v.efi
Mode=0444
TriesLeft=3
TriesDone=0
InstancesMax=2
EOF

    cat >"$CONFIGDIR/05-fifth.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=uki-extra-@v.efi

[Target]
Type=regular-file
Path=/EFI/Linux
PathRelativeTo=boot
MatchPattern=uki_@v.efi.extra.d/extra.addon.efi
Mode=0444
InstancesMax=2
EOF

    # Test with a transfer which contains one of the other transfers as a prefix
    # of its files, to check pattern matching can distinguish the two.
    cat >"$CONFIGDIR/06-sixth.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=linux-@v.erofs

[Target]
Type=regular-file
Path=$WORKDIR/system
MatchPattern=linux-@v.erofs
ReadOnly=yes
InstancesMax=4
EOF

    cat >"$CONFIGDIR/07-seventh.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=linux-@v.erofs.caibx

[Target]
Type=regular-file
Path=$WORKDIR/system
MatchPattern=linux-@v.erofs.caibx
ReadOnly=yes
InstancesMax=4
EOF

    cat >"$CONFIGDIR/optional.feature" <<EOF
[Feature]
Description=Optional Feature
EOF

    cat >"$CONFIGDIR/99-optional.transfer" <<EOF
[Transfer]
Features=optional

[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=optional-@v.efi

[Target]
Type=regular-file
Path=/EFI/Linux
PathRelativeTo=boot
MatchPattern=uki_@v.efi.extra.d/optional.efi
Mode=0444
InstancesMax=2
EOF

    rm -rf "${WORKDIR:?}"/{esp,xbootldr,source,system}
    mkdir -p "$WORKDIR"/{source,esp/EFI/Linux,xbootldr/EFI/Linux,system}

    # Install initial version and verify
    new_version "$sector_size" v1
    update_now "$update_type" "$client"
    verify_version_current "$blockdev" "$sector_size" v1 1

    # Create second version, update and verify that it is added
    new_version "$sector_size" v2
    update_now "$update_type" "$client"
    verify_version "$blockdev" "$sector_size" v1 1
    verify_version_current "$blockdev" "$sector_size" v2 2

    # Create third version, update and verify it replaced the first version
    new_version "$sector_size" v3
    update_now "$update_type" "$client"
    verify_version_current "$blockdev" "$sector_size" v3 1
    verify_version "$blockdev" "$sector_size" v2 2
    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v1+3-0.efi"
    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v1.efi.extra.d/extra.addon.efi"
    test ! -d "$WORKDIR/xbootldr/EFI/Linux/uki_v1.efi.extra.d"

    # Create fourth version, but make it be incomplete (i.e. missing some files)
    # on the server-side. Verify that it's not offered as an update.
    new_version "$sector_size" v4
    rm "$WORKDIR/source/uki-extra-v4.efi"
    update_checksums
    check_no_new_update_available "$client"

    # Create a fifth version, that's complete on the server side. We should
    # completely skip the incomplete v4 and install v5 instead.
    new_version "$sector_size" v5
    update_now "$update_type" "$client"
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2

    # Make the local installation of v5 incomplete by deleting a file, then make
    # sure that sysupdate still recognizes the installation and can complete it
    # in place
    # Always do this as a monolithic update for the repair to work.
    rm -r "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d"
    "$SYSUPDATE" --offline list v5 | grep "incomplete" >/dev/null
    update_now "monolithic" "$client"
    "$SYSUPDATE" --offline list v5 | grep -v "incomplete" >/dev/null
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2

    # Now let's try enabling an optional feature
    if [[ "$client" == "sysupdate-cli" ]]; then
        "$SYSUPDATE" features | grep "optional"
        "$SYSUPDATE" features optional | grep "99-optional"
    elif [[ "$client" == "varlink" ]]; then
        [[ $(varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.ListFeatures '{"target":{"class":"host"}}' | jq -r '.features[] | select(.id=="optional") | .description') == "Optional Feature" ]]
        varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.ListFeatures '{"target":{"class":"host"}}' | jq -r '.features[] | select(.id=="optional") | .transfers' | grep "99-optional"
    else
        exit 1
    fi

    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d/optional.efi"
    mkdir "$CONFIGDIR/optional.feature.d"
    echo -e "[Feature]\nEnabled=true" > "$CONFIGDIR/optional.feature.d/enable.conf"
    "$SYSUPDATE" --offline list v5 | grep "incomplete" >/dev/null
    update_now "$update_type" "$client"
    "$SYSUPDATE" --offline list v5 | grep -v "incomplete" >/dev/null
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2
    test -f "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d/optional.efi"

    # And now let's disable it and make sure it gets cleaned up
    rm -r "$CONFIGDIR/optional.feature.d"
    check_no_new_update_available "$client"
    "$SYSUPDATE" vacuum
    "$SYSUPDATE" --offline list v5 | grep -v "incomplete" >/dev/null
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2
    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d/optional.efi"

    # Create sixth version, update using updatectl and verify it replaced the
    # correct version
    new_version "$sector_size" v6
    if [[ -x "$UPDATECTL" ]]; then
        systemctl start systemd-sysupdated
        check_new_update_available "$client"
        "$UPDATECTL" update |& tee "$WORKDIR"/updatectl-update-6
        grep "Done" "$WORKDIR"/updatectl-update-6
        (! grep "Already up-to-date" "$WORKDIR"/updatectl-update-6)
    else
        # If no updatectl, gracefully fall back to systemd-sysupdate
        update_now "$update_type" "$client"
    fi
    # User-facing updatectl returns 0 if there's no updates, so use the low-level
    # utility to make sure we did upgrade
    check_no_new_update_available "$client"
    verify_version_current "$blockdev" "$sector_size" v6 1
    verify_version "$blockdev" "$sector_size" v5 2

    # Next, let's run updatectl's various inspection commands. We're not
    # testing for specific output, but this will at least catch obvious crashes
    # and allow updatectl to run under the various sanitizers. We create a
    # component so that updatectl has multiple targets to list.
    if [[ -x "$UPDATECTL" ]]; then
        mkdir -p /run/sysupdate.test.d/
        cp "$CONFIGDIR/01-first.transfer" /run/sysupdate.test.d/01-first.transfer
        verify_object_fields "$("$UPDATECTL" list 2>&1)"
        verify_object_fields "$("$UPDATECTL" list host 2>&1)"
        verify_object_fields "$("$UPDATECTL" list host@v6 2>&1)"
        "$UPDATECTL" check
        rm -r /run/sysupdate.test.d
    fi

    # Create seventh version, and update through a file:// URL. This should be
    # almost as good as testing HTTP, but is simpler for us to set up. file:// is
    # abstracted in curl for us, and since our main goal is to test our own code
    # (and not curl) this test should be quite good even if not comprehensive. This
    # will test the SHA256SUMS logic at least (we turn off GPG validation though,
    # see above)
    new_version "$sector_size" v7

    cat >"$CONFIGDIR/02-second.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=part2-@v.raw.gz

[Target]
Type=partition
Path=$blockdev
MatchPattern=a-very-long-partition-name-@v
MatchPartitionType=root-x86-64-verity
EOF

    cat >"$CONFIGDIR/03-third.transfer" <<EOF
[Source]
Type=url-tar
Path=file://$WORKDIR/source
MatchPattern=dir-@v.tar.gz

[Target]
Type=directory
Path=$WORKDIR/dirs
CurrentSymlink=$WORKDIR/dirs/current
MatchPattern=dir-@v
InstancesMax=3
EOF

    update_now "$update_type" "$client"
    verify_version "$blockdev" "$sector_size" v6 1
    verify_version_current "$blockdev" "$sector_size" v7 2

    # Check with a best before in the past
    update_checksums_with_best_before "$(date -u +'%Y-%m-%d' -d 'last month')"
    (! "$SYSUPDATE" --verify=no update)

    # Retry but force check off
    SYSTEMD_SYSUPDATE_VERIFY_FRESHNESS=0 "$SYSUPDATE" --verify=no update

    # Check with best before in the future
    update_checksums_with_best_before "$(date -u +'%Y-%m-%d' -d 'next month')"
    "$SYSUPDATE" --verify=no update

    # Check again without a best before
    update_checksums
    "$SYSUPDATE" --verify=no update

    # Let's make sure that we don't break our backwards-compat for .conf files
    # (what .transfer files were called before v257)
    for i in "$CONFIGDIR/"*.conf; do echo mv "$i" "${i%.conf}.transfer"; done
    new_version "$sector_size" v8
    update_now "$update_type" "$client"
    verify_version_current "$blockdev" "$sector_size" v8 1
    verify_version "$blockdev" "$sector_size" v7 2

    # Create a 9th version but corrupt the checksum in SHA256SUMS so pulling it
    # fails when verifying the checksum, in order to create a current+partial
    # state. Try to update again and verify that this results in an error.
    # Vacuum the partial version, regenerate it on the server, try updating
    # again and it should succeed.
    new_version "$sector_size" v9 "corrupt-checksum"
    (! update_now "$update_type" "$client")
    "$SYSUPDATE" --offline list v9 | grep "partial" >/dev/null
    verify_version_current "$blockdev" "$sector_size" v8 1
    # don’t verify the other part of the block device as it’s in an indeterminate state
    (! update_now "$update_type" "$client" "no-checks") |& tee "$WORKDIR"/update_now-9
    cat "$WORKDIR"/update_now-9
    grep "is already acquired and partially installed. Vacuum it to try installing again." "$WORKDIR"/update_now-9
    "$SYSUPDATE" --offline vacuum |& grep "Removing old partial" >/dev/null
    verify_version_current "$blockdev" "$sector_size" v8 1
    # don’t verify the other part of the block device as it’s in an indeterminate state
    "$SYSUPDATE" --verify=no list v9 | grep "candidate" >/dev/null
    new_version "$sector_size" v9
    update_now "$update_type" "$client"
    verify_version "$blockdev" "$sector_size" v8 1
    verify_version_current "$blockdev" "$sector_size" v9 2

    # Test that checking for an update on a non-existent target fails
    # (for backwards compatibility reasons, the validation in sysupdate-cli is
    # less strict)
    if [[ "$client" == "sysupdate-cli" ]]; then
        (! "$SYSUPDATE" --verify=no check-new --component=../) |& grep "Component name invalid" >/dev/null
    elif [[ "$client" == "varlink" ]]; then
        (! varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.CheckNew '{"target":{"class":"component","name":"../"}}') |& grep org.varlink.service.InvalidParameter >/dev/null
        (! varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.CheckNew '{"target":{"class":"component","name":"doesnotexist"}}') |& grep io.systemd.SysUpdate.NoSuchTarget >/dev/null
    else
        exit 1
    fi

    # Cleanup
    [[ -b "$blockdev" ]] && losetup --detach "$blockdev"
    rm "$BACKING_FILE"
done
done
done

# Regression test for https://github.com/systemd/systemd/issues/41501 — check
# that a ‘default’ component is only listed by sysupdate if it’s fully configured
mv "$CONFIGDIR" "$CONFIGDIR.backup"
mkdir -p /run/sysupdate.some-component.d
tee /run/sysupdate.some-component.d/portable.transfer << EOF
[Transfer]
ChangeLog=https://example.com/changelog/@v
Verify=no

[Source]
Type=url-tar
Path=https://example.com/does-not-matter/@v.tar.xz
MatchPattern=some-component_@v-portable.tar.xz

[Target]
Type=directory
Path=/var/lib/portables
MatchPattern=some-component_@v
CurrentSymlink=some-component
EOF
"$SYSUPDATE" --json=short components | grep -F '{"default":false,"components":["some-component"]}' >/dev/null
varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.ListTargets | jq -e '.targets | all(.id.class != "host")' >/dev/null
mkdir /run/sysupdate.d
"$SYSUPDATE" --json=short components | grep -F '{"default":false,"components":["some-component"]}' >/dev/null
varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.ListTargets | jq -e '.targets | all(.id.class != "host")' >/dev/null
[[ $(varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.ListTargets | jq -r '.targets[0].id.name') == "some-component" ]]

# Regression test for https://github.com/systemd/systemd/issues/42330 — the
# 'pending'/'reboot' verbs and the '--reboot' switch compare the newest installed
# version against the booted OS version (IMAGE_VERSION= from os-release), which is
# unrelated to component versions. Selecting a component must therefore be refused
# rather than silently performing a bogus comparison.
(! "$SYSUPDATE" --component=some-component pending) |& grep -F 'may not be combined' >/dev/null
(! "$SYSUPDATE" --component=some-component reboot) |& grep -F 'may not be combined' >/dev/null
(! "$SYSUPDATE" --component=some-component update --reboot) |& grep -F 'may not be combined' >/dev/null

# Clean up regression test
rmdir /run/sysupdate.d
rm -rf /run/sysupdate.some-component.d
mv "$CONFIGDIR.backup" "$CONFIGDIR"

# Make sure the processing of compressed streams still handles uncompressed streams shorter than
# COMPRESSION_MAGIC_BYTES_MAX correctly.
rm -rf "$CONFIGDIR" "$WORKDIR/blobs"
mkdir -p "$CONFIGDIR" "$WORKDIR/blobs"
printf 'xx' >"$WORKDIR/source/tiny-v1.bin"
(cd "$WORKDIR/source" && sha256sum tiny-v1.bin >SHA256SUMS)
cat >"$CONFIGDIR/01-tiny-url.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=tiny-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=tiny-@v.bin
InstancesMax=1
EOF

"$SYSUPDATE" --verify=no update
cmp "$WORKDIR/source/tiny-v1.bin" "$WORKDIR/blobs/tiny-v1.bin"

# Test that listing features when none are configured gives an empty list.
"$SYSUPDATE" features |& grep "No features." >/dev/null
[[ $(varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.ListFeatures '{"target":{"class":"host"}}' | jq -r '.features') == "[]" ]]

# Cleanup
rm "$CONFIGDIR/01-tiny-url.transfer"
rm "$WORKDIR/source/tiny-v1.bin"
rm "$WORKDIR/source/SHA256SUMS"

# Check that malformed manifest hashes are rejected without aborting.
rm -rf "$WORKDIR/malformed-manifest"
mkdir -p "$WORKDIR/malformed-manifest/definitions" "$WORKDIR/malformed-manifest/source" "$WORKDIR/malformed-manifest/target"
printf 'payload\n' >"$WORKDIR/malformed-manifest/source/malformed-v1.bin"
hash_64=0000000000000000000000000000000000000000000000000000000000000000
printf '%s\t\t *malformed-v1.bin\n' "${hash_64%??}" >"$WORKDIR/malformed-manifest/source/SHA256SUMS"
cat >"$WORKDIR/malformed-manifest/definitions/01-malformed-hash.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/malformed-manifest/source
MatchPattern=malformed-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/malformed-manifest/target
MatchPattern=malformed-@v.bin
InstancesMax=1
EOF
set +e
"$SYSUPDATE" --definitions="$WORKDIR/malformed-manifest/definitions" --verify=no check-new &>"$WORKDIR/malformed-manifest/check-new.log"
rc=$?
set -e
[[ $rc -ne 0 ]]
[[ $rc -ne 134 ]]
grep -F "Manifest hash at line 1 decoded to 31 bytes" "$WORKDIR/malformed-manifest/check-new.log" >/dev/null

# Check the "cleanup" verb and the underlying install database. A successful
# update must record an install database entry for every transfer that installs
# into the file system, and those entries must cover all installed resources
# (regular files as well as directories). Once the transfer file owning some
# resources is removed, "systemd-sysupdate cleanup" must delete the now-orphaned
# resources (and their install database entries), while leaving resources that
# are still owned by a transfer file untouched.
INSTALLDB="/var/lib/systemd/sysupdate/installdb"
CLEANUP="$WORKDIR/cleanup"
rm -rf "$CONFIGDIR" "$INSTALLDB" "$CLEANUP"
mkdir -p "$CONFIGDIR" "$CLEANUP/source" "$CLEANUP/target"

# The "alpha" transfer installs plain regular files, while the "beta" transfer
# installs whole directories (each populated with a couple of files), to exercise
# the recursive removal of orphaned directory resources during cleanup.
cleanup_new_version() {
    local version="${1:?}"
    echo "$RANDOM" >"$CLEANUP/source/alpha-$version.bin"
    rm -rf "$CLEANUP/source/beta-$version"
    mkdir -p "$CLEANUP/source/beta-$version"
    echo "$RANDOM" >"$CLEANUP/source/beta-$version/one.txt"
    echo "$RANDOM" >"$CLEANUP/source/beta-$version/two.txt"
    (cd "$CLEANUP/source" && sha256sum alpha-* >SHA256SUMS)
}

# Number of install database entries (symlinks) currently recorded.
installdb_count() {
    if [[ -d "$INSTALLDB" ]]; then
        find "$INSTALLDB" -mindepth 1 -maxdepth 1 -type l | wc -l
    else
        echo 0
    fi
}

# Assert that every resource (file or directory) currently installed in the
# target directory is covered by at least one install database entry (i.e. its
# name matches a recorded pattern that points at the target directory).
assert_installdb_covers_target() {
    local f base link tgt path pattern glob covered
    for f in "$CLEANUP/target"/*; do
        [[ -e "$f" ]] || continue
        base="$(basename "$f")"
        covered=0
        while read -r link; do
            tgt="$(readlink "$link")"
            # Entries are stored as "<path>/./<pattern>".
            path="${tgt%%/./*}"
            pattern="${tgt#*/./}"
            # Translate the sysupdate pattern into a shell glob (only @v is used here).
            glob="${pattern//@v/*}"
            # shellcheck disable=SC2053
            if [[ "$path" == "$CLEANUP/target" && "$base" == $glob ]]; then
                covered=1
                break
            fi
        done < <(find "$INSTALLDB" -mindepth 1 -maxdepth 1 -type l)
        [[ "$covered" -eq 1 ]] || { echo "Installed resource '$f' not covered by install database" >&2; exit 1; }
    done
}

# Verify the installed beta-<version> directory matches its source.
verify_beta_synced() {
    local version="${1:?}"
    test -d "$CLEANUP/target/beta-$version"
    cmp "$CLEANUP/source/beta-$version/one.txt" "$CLEANUP/target/beta-$version/one.txt"
    cmp "$CLEANUP/source/beta-$version/two.txt" "$CLEANUP/target/beta-$version/two.txt"
}

cat >"$CONFIGDIR/01-alpha.transfer" <<EOF
[Source]
Type=regular-file
Path=$CLEANUP/source
MatchPattern=alpha-@v.bin

[Target]
Type=regular-file
Path=$CLEANUP/target
MatchPattern=alpha-@v.bin
InstancesMax=2
EOF

cat >"$CONFIGDIR/02-beta.transfer" <<EOF
[Source]
Type=directory
Path=$CLEANUP/source
MatchPattern=beta-@v

[Target]
Type=directory
Path=$CLEANUP/target
MatchPattern=beta-@v
InstancesMax=2
EOF

# Install two versions; with InstancesMax=2 both are kept for each transfer.
cleanup_new_version v1
"$SYSUPDATE" --verify=no update
cleanup_new_version v2
"$SYSUPDATE" --verify=no update

# All four resources must be installed, and the directory resources must have
# been synced over completely.
test -f "$CLEANUP/target/alpha-v1.bin"
test -f "$CLEANUP/target/alpha-v2.bin"
verify_beta_synced v1
verify_beta_synced v2

# The update must have recorded one install database entry per transfer pattern,
# and those entries must cover every installed resource.
[[ "$(installdb_count)" -eq 2 ]]
assert_installdb_covers_target

# Running cleanup while all transfer files are still in place must be a no-op:
# nothing is orphaned, so nothing must be removed.
"$SYSUPDATE" cleanup
test -f "$CLEANUP/target/alpha-v1.bin"
test -f "$CLEANUP/target/alpha-v2.bin"
verify_beta_synced v1
verify_beta_synced v2
[[ "$(installdb_count)" -eq 2 ]]
assert_installdb_covers_target

# Remove the transfer file owning the "beta" directories and clean up. The beta
# directories (with all their contents) and their install database entry must be
# removed, while the alpha files must be kept since their transfer file is still
# in place.
rm "$CONFIGDIR/02-beta.transfer"
"$SYSUPDATE" cleanup
test -f "$CLEANUP/target/alpha-v1.bin"
test -f "$CLEANUP/target/alpha-v2.bin"
test ! -e "$CLEANUP/target/beta-v1"
test ! -e "$CLEANUP/target/beta-v2"
[[ "$(installdb_count)" -eq 1 ]]
assert_installdb_covers_target

# Now remove the remaining transfer file and clean up again. The alpha files and
# the last install database entry must be removed too.
rm "$CONFIGDIR/01-alpha.transfer"
"$SYSUPDATE" cleanup
test ! -f "$CLEANUP/target/alpha-v1.bin"
test ! -f "$CLEANUP/target/alpha-v2.bin"
[[ "$(installdb_count)" -eq 0 ]]

rm -rf "$CONFIGDIR" "$INSTALLDB" "$CLEANUP"

# Briefly check the "--component-all" switch of the "cleanup" verb. Each component
# keeps its own install database (installdb.<component>), and "cleanup
# --component-all" must clean up orphaned resources across *all* of them in one
# go. Set up two components, install a resource into each, then drop both transfer
# files and run a single "cleanup --component-all" — it must remove both
# components' resources (and their install database entries).
COMPALL="$WORKDIR/component-all"
rm -rf "$COMPALL" /run/sysupdate.comp-a.d /run/sysupdate.comp-b.d \
    /var/lib/systemd/sysupdate/installdb.comp-a /var/lib/systemd/sysupdate/installdb.comp-b
mkdir -p "$COMPALL/source" "$COMPALL/target-a" "$COMPALL/target-b" \
    /run/sysupdate.comp-a.d /run/sysupdate.comp-b.d

echo "$RANDOM" >"$COMPALL/source/comp-a-v1.bin"
echo "$RANDOM" >"$COMPALL/source/comp-b-v1.bin"
(cd "$COMPALL/source" && sha256sum comp-* >SHA256SUMS)

cat >/run/sysupdate.comp-a.d/01-comp-a.transfer <<EOF
[Source]
Type=regular-file
Path=$COMPALL/source
MatchPattern=comp-a-@v.bin

[Target]
Type=regular-file
Path=$COMPALL/target-a
MatchPattern=comp-a-@v.bin
InstancesMax=1
EOF

cat >/run/sysupdate.comp-b.d/01-comp-b.transfer <<EOF
[Source]
Type=regular-file
Path=$COMPALL/source
MatchPattern=comp-b-@v.bin

[Target]
Type=regular-file
Path=$COMPALL/target-b
MatchPattern=comp-b-@v.bin
InstancesMax=1
EOF

"$SYSUPDATE" --component=comp-a --verify=no update
"$SYSUPDATE" --component=comp-b --verify=no update
test -f "$COMPALL/target-a/comp-a-v1.bin"
test -f "$COMPALL/target-b/comp-b-v1.bin"
test -d /var/lib/systemd/sysupdate/installdb.comp-a
test -d /var/lib/systemd/sysupdate/installdb.comp-b

# --component-all is not supported for every verb, so it must be refused where it isn't (e.g. "vacuum").
# (It *is* supported for update/acquire/cleanup/enable-*/disable-*, which is exercised further down.)
(! "$SYSUPDATE" --component-all --verify=no vacuum)

# With the transfer files still in place "cleanup --component-all" is a no-op:
# nothing is orphaned.
"$SYSUPDATE" --component-all cleanup
test -f "$COMPALL/target-a/comp-a-v1.bin"
test -f "$COMPALL/target-b/comp-b-v1.bin"

# Drop both transfer files and clean up all components at once. Both resources
# (and their install database entries) must now be gone.
rm /run/sysupdate.comp-a.d/01-comp-a.transfer /run/sysupdate.comp-b.d/01-comp-b.transfer
"$SYSUPDATE" --component-all cleanup
test ! -e "$COMPALL/target-a/comp-a-v1.bin"
test ! -e "$COMPALL/target-b/comp-b-v1.bin"
[[ "$(find /var/lib/systemd/sysupdate/installdb.comp-a -type l | wc -l)" -eq 0 ]]
[[ "$(find /var/lib/systemd/sysupdate/installdb.comp-b -type l | wc -l)" -eq 0 ]]

rm -rf "$COMPALL" /run/sysupdate.comp-a.d /run/sysupdate.comp-b.d \
    /var/lib/systemd/sysupdate/installdb.comp-a /var/lib/systemd/sysupdate/installdb.comp-b

# Check the "--cleanup=" switch of the "update" verb. With "--cleanup=yes" a
# successful update must, after installing the new version, run the equivalent of
# the "cleanup" verb and remove any resources that are no longer owned by a
# currently defined transfer file. Reuse the "alpha"/"beta" helpers from above.
rm -rf "$CONFIGDIR" "$INSTALLDB" "$CLEANUP"
mkdir -p "$CONFIGDIR" "$CLEANUP/source" "$CLEANUP/target"

cat >"$CONFIGDIR/01-alpha.transfer" <<EOF
[Source]
Type=regular-file
Path=$CLEANUP/source
MatchPattern=alpha-@v.bin

[Target]
Type=regular-file
Path=$CLEANUP/target
MatchPattern=alpha-@v.bin
InstancesMax=2
EOF

cat >"$CONFIGDIR/02-beta.transfer" <<EOF
[Source]
Type=directory
Path=$CLEANUP/source
MatchPattern=beta-@v

[Target]
Type=directory
Path=$CLEANUP/target
MatchPattern=beta-@v
InstancesMax=2
EOF

# Install a first version with both transfers in place.
cleanup_new_version v1
"$SYSUPDATE" --verify=no update --cleanup=yes
test -f "$CLEANUP/target/alpha-v1.bin"
verify_beta_synced v1
[[ "$(installdb_count)" -eq 2 ]]
assert_installdb_covers_target

# Now drop the "beta" transfer file and install a second version with
# "--cleanup=yes". The new alpha resource must be installed, and the now-orphaned
# beta directory (and its install database entry) must be removed as part of the
# same invocation, without a separate "cleanup" call.
rm "$CONFIGDIR/02-beta.transfer"
cleanup_new_version v2
"$SYSUPDATE" --verify=no update --cleanup=yes
test -f "$CLEANUP/target/alpha-v1.bin"
test -f "$CLEANUP/target/alpha-v2.bin"
test ! -e "$CLEANUP/target/beta-v1"
[[ "$(installdb_count)" -eq 1 ]]
assert_installdb_covers_target

# With "--cleanup=no" (the default) orphaned resources must be left in place.
# Redefine the "alpha" transfer so its patterns no longer match the already
# installed alpha files (turning them into orphans), while keeping a valid
# transfer definition in place. Updating with "--cleanup=no" must then install
# nothing new (there's no matching source) and leave the now-orphaned alpha files
# and their install database entry untouched.
cat >"$CONFIGDIR/01-alpha.transfer" <<EOF
[Source]
Type=regular-file
Path=$CLEANUP/source
MatchPattern=gamma-@v.bin

[Target]
Type=regular-file
Path=$CLEANUP/target
MatchPattern=gamma-@v.bin
InstancesMax=2
EOF
"$SYSUPDATE" --verify=no update --cleanup=no
test -f "$CLEANUP/target/alpha-v1.bin"
test -f "$CLEANUP/target/alpha-v2.bin"
[[ "$(installdb_count)" -eq 1 ]]

# Invoking the "cleanup" verb with "--cleanup=no" is contradictory and must be
# refused.
(! "$SYSUPDATE" --cleanup=no cleanup) |& grep "contradictory" >/dev/null

# A plain "cleanup" must still remove the orphaned alpha files.
"$SYSUPDATE" cleanup
test ! -f "$CLEANUP/target/alpha-v1.bin"
test ! -f "$CLEANUP/target/alpha-v2.bin"
[[ "$(installdb_count)" -eq 0 ]]

rm -rf "$CONFIGDIR" "$INSTALLDB" "$CLEANUP"

# Verify the notification callout: after a successful update, sysupdate must connect to every socket in
# /run/systemd/sysupdate/notify/ and invoke io.systemd.SysUpdate.Notify.OnCompletedUpdate(). We hook a tiny
# recorder socket into that directory that captures the request and replies with success.
NOTIFY_LOG="$WORKDIR/notify.log"
rm -f "$NOTIFY_LOG"

cat >"$WORKDIR/notify-recorder.py" <<EOF
#!/usr/bin/env python3
# Minimal Varlink server: read one NUL-terminated request, record it, reply with empty parameters.
import sys
buf = b""
while True:
    c = sys.stdin.buffer.read(1)
    if not c or c == b"\x00":
        break
    buf += c
with open("$NOTIFY_LOG", "ab") as f:
    f.write(buf + b"\n")
sys.stdout.buffer.write(b'{"parameters":{}}\x00')
sys.stdout.buffer.flush()
EOF
chmod +x "$WORKDIR/notify-recorder.py"

cat >/run/systemd/system/test-sysupdate-notify-recorder.socket <<EOF
[Socket]
ListenStream=/run/systemd/sysupdate/notify/io.test.SysUpdateRecorder
Accept=yes
EOF

cat >"/run/systemd/system/test-sysupdate-notify-recorder@.service" <<EOF
[Service]
ExecStart=$WORKDIR/notify-recorder.py
StandardInput=socket
StandardOutput=socket
EOF

systemctl daemon-reload
systemctl start test-sysupdate-notify-recorder.socket

rm -rf "$CONFIGDIR" "$WORKDIR/blobs"
mkdir -p "$CONFIGDIR" "$WORKDIR/blobs"
echo "hello" >"$WORKDIR/source/notifytest-v1.bin"
(cd "$WORKDIR/source" && sha256sum notifytest-v1.bin >SHA256SUMS)
cat >"$CONFIGDIR/01-notifytest.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=notifytest-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=notifytest-@v.bin
InstancesMax=1
EOF

# A real update must trigger exactly one notification carrying the version and the updated resources.
# The callout is synchronous (sysupdate blocks until the subscriber replied, which happens after the
# request was recorded), so the log is fully written by the time the update returns.
"$SYSUPDATE" --verify=no update
test -s "$NOTIFY_LOG"  # the notification must have been recorded
notify_line="$(tail -n1 "$NOTIFY_LOG")"
echo "Recorded notification: $notify_line"
jq -e '.method == "io.systemd.SysUpdate.Notify.OnCompletedUpdate"' <<<"$notify_line" >/dev/null
jq -e '.parameters.version == "v1"' <<<"$notify_line" >/dev/null
jq -e '.parameters.resources | length >= 1' <<<"$notify_line" >/dev/null
jq -e '.parameters.resources | all(has("transfer"))' <<<"$notify_line" >/dev/null

# A no-op update ("No update needed") must NOT emit a notification.
rm -f "$NOTIFY_LOG"
"$SYSUPDATE" --verify=no update
test ! -s "$NOTIFY_LOG"

systemctl stop test-sysupdate-notify-recorder.socket
rm -f /run/systemd/system/test-sysupdate-notify-recorder.socket \
      /run/systemd/system/test-sysupdate-notify-recorder@.service
systemctl daemon-reload
rm -rf "$CONFIGDIR" "$WORKDIR/blobs"
rm -f "$WORKDIR/source/notifytest-v1.bin" "$WORKDIR/source/SHA256SUMS" \
      "$WORKDIR/notify-recorder.py" "$NOTIFY_LOG"

test_signature_verification() {
    if ! command -v gpg >/dev/null; then
        echo "gpg not available, skipping signature verification test"
        return 0
    fi

    # Checking for --auto-key-import is not enough because the merge-only/import-clean guarantee we rely on
    # only works correctly with gpg 2.4
    local gpg_version gpg_rest
    gpg_version="$(gpg --version | sed -n '1p' | awk '{print $NF}')"
    gpg_rest="${gpg_version#*.}"
    if [ "${gpg_version%%.*}" -lt 2 ] || { [ "${gpg_version%%.*}" -eq 2 ] && [ "${gpg_rest%%.*}" -lt 4 ]; }; then
        echo "gpg $gpg_version too old (need >= 2.4), skipping signature verification test"
        return 0
    fi

    local sigdir="$WORKDIR/sigtest-source"
    local defdir="$WORKDIR/sigtest-defs"
    local gpghome="$WORKDIR/sigtest-gpghome"
    local other_home="$WORKDIR/sigtest-otherhome"
    local target="$WORKDIR/sigtest-target"
    local keyring="$WORKDIR/sigtest-keyring"
    local top_fpr keys

    SIGTEST_GPGHOME="$gpghome"
    SIGTEST_OTHERHOME="$other_home"

    mkdir -p "$sigdir" "$defdir" "$gpghome" "$other_home" "$target"
    chmod 700 "$gpghome" "$other_home"

    GNUPGHOME="$gpghome" gpg --batch --pinentry-mode loopback --passphrase '' \
        --quick-gen-key 'Test Key <test@example.com>' rsa2048 cert,sign never
    # Capture gpg output first, then grep from a here-string to avoid grep -m1 causing a SIGPIPE
    keys="$(GNUPGHOME="$gpghome" gpg --list-keys --with-colons)"
    top_fpr="$(grep -m1 '^fpr:' <<< "$keys" | cut -d: -f10)"
    test "$top_fpr" != ""

    GNUPGHOME="$gpghome" gpg --export --output "$keyring"

    dd if=/dev/urandom of="$sigdir/payload-v1.raw" bs=1024 count=8 status=none
    (cd "$sigdir" && sha256sum payload-v1.raw > SHA256SUMS)
    GNUPGHOME="$gpghome" gpg --batch --pinentry-mode loopback --passphrase '' \
        --detach-sign --include-key-block --yes \
        --output "$sigdir/SHA256SUMS.gpg" "$sigdir/SHA256SUMS"

    cat >"$defdir/01-sigtest.transfer" <<EOF
[Source]
Type=url-file
Path=file://$sigdir
MatchPattern=payload-@v.raw

[Target]
Type=regular-file
Path=$target
MatchPattern=payload-@v.raw
InstancesMax=3
EOF

    SYSTEMD_OPENPGP_KEYRING="$keyring" "$SYSUPDATE" --definitions="$defdir" check-new
    SYSTEMD_OPENPGP_KEYRING="$keyring" "$SYSUPDATE" --definitions="$defdir" update
    cmp "$sigdir/payload-v1.raw" "$target/payload-v1.raw"

    # Negative test: Sign with a key not in the keyring
    GNUPGHOME="$other_home" gpg --batch --pinentry-mode loopback --passphrase '' \
        --quick-gen-key 'Other Key <other@example.com>' rsa2048 cert,sign never
    dd if=/dev/urandom of="$sigdir/payload-v2.raw" bs=1024 count=8 status=none
    (cd "$sigdir" && sha256sum payload-v1.raw payload-v2.raw > SHA256SUMS)
    GNUPGHOME="$other_home" gpg --batch --pinentry-mode loopback --passphrase '' \
        --detach-sign --include-key-block --yes \
        --output "$sigdir/SHA256SUMS.gpg" "$sigdir/SHA256SUMS"
    if SYSTEMD_OPENPGP_KEYRING="$keyring" "$SYSUPDATE" --definitions="$defdir" update; then
        echo "ERROR: accepted an update signed by a key not in the keyring" >&2
        exit 1
    fi
    if [ -f "$target/payload-v2.raw" ]; then
        echo "ERROR: payload-v2 should not have been installed" >&2
        exit 1
    fi

    # Sub key test: Add a sub key the client does not have and rely on gpg
    # --auto-key-import to get it from the signature.
    GNUPGHOME="$gpghome" gpg --batch --pinentry-mode loopback --passphrase '' \
        --quick-add-key "$top_fpr" rsa2048 sign 1y
    # Make it so that only the sub key is available for signing to avoid having
    # to select it by fingerprint.
    GNUPGHOME="$gpghome" gpg --batch --pinentry-mode loopback --passphrase '' \
        --output "$WORKDIR/sigtest-subkey-secret.gpg" \
        --export-secret-subkeys
    GNUPGHOME="$gpghome" gpg --batch --pinentry-mode loopback --passphrase '' \
        --yes --delete-secret-keys "$top_fpr"
    GNUPGHOME="$gpghome" gpg --batch --pinentry-mode loopback --passphrase '' \
        --import "$WORKDIR/sigtest-subkey-secret.gpg"
    GNUPGHOME="$gpghome" gpg --batch --pinentry-mode loopback --passphrase '' \
        --detach-sign --include-key-block --yes \
        --output "$sigdir/SHA256SUMS.gpg" "$sigdir/SHA256SUMS"
    SYSTEMD_OPENPGP_KEYRING="$keyring" "$SYSUPDATE" --definitions="$defdir" update
    cmp "$sigdir/payload-v2.raw" "$target/payload-v2.raw"
}

test_signature_verification

# Test '**/' as prefix in MatchPattern= for subpaths in SHA256SUMS
rm -rf "$CONFIGDIR" "$WORKDIR/blobs" "$WORKDIR/source/sub"
mkdir -p "$CONFIGDIR" "$WORKDIR/blobs" "$WORKDIR/source/sub"

printf '1234567' >"$WORKDIR/source/sub/blob-v10.bin"
printf 'abcdefg' >"$WORKDIR/source/sub/blob-v11.bin"
(cd "$WORKDIR/source" && rm -f BEST-BEFORE-* && sha256sum sub/blob-*.bin >SHA256SUMS)

# A regular-file source where '**/' descends into sub/ to match against the basename
cat >"$CONFIGDIR/01-basename-dir.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=**/blob-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=blob-@v.bin
InstancesMax=1
EOF
"$SYSUPDATE" --verify=no update
cmp "$WORKDIR/source/sub/blob-v11.bin" "$WORKDIR/blobs/blob-v11.bin"
[[ "$("$SYSUPDATE" --verify=no list v11 | grep -c "Version: v11")" == "1" ]]
rm "$CONFIGDIR/01-basename-dir.transfer"

# A url-file source pulled via file:// using SHA256SUMS with "sub/blob-v1x.bin" entries
rm -rf "$WORKDIR/blobs"
mkdir -p "$WORKDIR/blobs"
cat >"$CONFIGDIR/01-basename-url.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=**/blob-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=blob-@v.bin
InstancesMax=1
EOF
"$SYSUPDATE" --verify=no update
cmp "$WORKDIR/source/sub/blob-v11.bin" "$WORKDIR/blobs/blob-v11.bin"
rm "$CONFIGDIR/01-basename-url.transfer"

# A pattern that spells out the subdir literally should also work for url sources
# for parity with regular-file sources
rm -rf "$WORKDIR/blobs"
mkdir -p "$WORKDIR/blobs"
cat >"$CONFIGDIR/01-explicit-url.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=sub/blob-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=blob-@v.bin
InstancesMax=1
EOF
"$SYSUPDATE" --verify=no update
cmp "$WORKDIR/source/sub/blob-v11.bin" "$WORKDIR/blobs/blob-v11.bin"
rm "$CONFIGDIR/01-explicit-url.transfer"

# Rejection test for a manifest entry containing ".."
rm -rf "$WORKDIR/blobs"
mkdir -p "$WORKDIR/blobs"
mkdir -p "$WORKDIR/source/sub/nested"
cp "$WORKDIR/source/SHA256SUMS" "$WORKDIR/source/SHA256SUMS.bak"
sed -i 's,sub/,sub/nested/../,g' "$WORKDIR/source/SHA256SUMS"
cat >"$CONFIGDIR/01-basename-url.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=**/blob-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=blob-@v.bin
EOF
if "$SYSUPDATE" --verify=no update |& tee "$WORKDIR/traversal.log"; then
    echo "ERROR: accepted a manifest entry with a '..' path traversal" >&2
    exit 1
fi
grep "Invalid filename" "$WORKDIR/traversal.log" >/dev/null
mv "$WORKDIR/source/SHA256SUMS.bak" "$WORKDIR/source/SHA256SUMS"
rm "$CONFIGDIR/01-basename-url.transfer"

# Rejection test for a manifest entry with a percent-encoded ".." which curl would
# decode when pulling via file://, escaping the source dir past path_is_normalized()
rm -rf "$WORKDIR/blobs"
mkdir -p "$WORKDIR/blobs"
cp "$WORKDIR/source/SHA256SUMS" "$WORKDIR/source/SHA256SUMS.bak"
sed -i 's,sub/,sub/nested/%2e%2e/,g' "$WORKDIR/source/SHA256SUMS"
cat >"$CONFIGDIR/01-basename-url.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=**/blob-@v.bin

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=blob-@v.bin
EOF
if "$SYSUPDATE" --verify=no update |& tee "$WORKDIR/percent.log"; then
    echo "ERROR: accepted a manifest entry with a percent-encoded '..' path traversal" >&2
    exit 1
fi
grep "Invalid filename" "$WORKDIR/percent.log" >/dev/null
mv "$WORKDIR/source/SHA256SUMS.bak" "$WORKDIR/source/SHA256SUMS"
rm "$CONFIGDIR/01-basename-url.transfer"

# A MatchPattern= with two subdirectory levels must descend beyond the first level
rm -rf "$CONFIGDIR" "$WORKDIR/blobs" "$WORKDIR/source/depth-v3"
mkdir -p "$CONFIGDIR" "$WORKDIR/blobs" "$WORKDIR/source/depth-v3/contents"
printf 'version-three' >"$WORKDIR/source/depth-v3/contents/image.raw"
cat >"$CONFIGDIR/01-depth.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=depth-@v/contents/image.raw

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=depth-@v.raw
InstancesMax=1
EOF
"$SYSUPDATE" --verify=no update
cmp "$WORKDIR/source/depth-v3/contents/image.raw" "$WORKDIR/blobs/depth-v3.raw"
rm -rf "$CONFIGDIR/01-depth.transfer" "$WORKDIR/source/depth-v3"

# Pattern matching should not depend on the pattern order. A transfer can list one pattern per repository
# layout, e.g., when a source switches from one directory per version (bundle-v1/image.raw) to flat files
# (bundle-v2.raw) and both layouts coexist during a migration.
# Check that after a subdirectory pattern which descends we still can match a top-level file through a
# '**/' pattern.
# Also check that after a non-matching '**/' pattern we still can match a plain top-level file.
# Then check that after a subdirectory pattern we can still match a plain top-level file.
# The first and last work because the wildcard field also captures the '.raw' suffix, so the top-level file
# matches the directory component of the subdirectory pattern and triggers the descend-retry logic.
# The fourth transfer checks the vice versa migration where one directory per version is the new layout and
# the old versions are flat files without a suffix: the directory name fully matches the flat pattern but
# must still be descended into for the subdirectory pattern.
rm -rf "$CONFIGDIR" "$WORKDIR/blobs" "$WORKDIR/source/bundle-v1" "$WORKDIR/source/pack-v2"
mkdir -p "$CONFIGDIR" "$WORKDIR/blobs"/{glob-last,glob-first,subdir-first,yes-and-retry} \
         "$WORKDIR/source/bundle-v1" "$WORKDIR/source/pack-v2"
echo 'version-one' >"$WORKDIR/source/bundle-v1/image.raw"
echo 'version-two' >"$WORKDIR/source/bundle-v2.raw"
echo 'version-v1' >"$WORKDIR/source/pack-v1"
echo 'version-v2' >"$WORKDIR/source/pack-v2/image.raw"
cat >"$CONFIGDIR/01-glob-last.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=bundle-@v/image.raw **/bundle-@v.raw

[Target]
Type=regular-file
Path=$WORKDIR/blobs/glob-last
MatchPattern=bundle-@v.raw
InstancesMax=1
EOF
cat >"$CONFIGDIR/02-glob-first.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=**/bundle-@v.img bundle-@v.raw

[Target]
Type=regular-file
Path=$WORKDIR/blobs/glob-first
MatchPattern=bundle-@v.raw
InstancesMax=1
EOF
cat >"$CONFIGDIR/03-subdir-first.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=bundle-@v/image.raw bundle-@v.raw

[Target]
Type=regular-file
Path=$WORKDIR/blobs/subdir-first
MatchPattern=bundle-@v.raw
InstancesMax=1
EOF
cat >"$CONFIGDIR/04-yes-and-retry.transfer" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=pack-@v/image.raw pack-@v

[Target]
Type=regular-file
Path=$WORKDIR/blobs/yes-and-retry
MatchPattern=pack-@v
InstancesMax=1
EOF
"$SYSUPDATE" --verify=no update
for target in glob-last glob-first subdir-first; do
    cmp "$WORKDIR/source/bundle-v2.raw" "$WORKDIR/blobs/$target/bundle-v2.raw"
done
cmp "$WORKDIR/source/pack-v2/image.raw" "$WORKDIR/blobs/yes-and-retry/pack-v2"
rm -rf "$CONFIGDIR"/{01-glob-last,02-glob-first,03-subdir-first,04-yes-and-retry}.transfer \
       "$WORKDIR/source/bundle-v2.raw" "$WORKDIR/source/bundle-v1" \
       "$WORKDIR/source/pack-v1" "$WORKDIR/source/pack-v2"

# A manifest entry that both directly matches a flat pattern and prefix-matches a subdirectory pattern
# must be downloaded, here the flat file is the newest version (this exercises YES_AND_RETRY)
rm -rf "$CONFIGDIR" "$WORKDIR/blobs" "$WORKDIR/source/pack-v1"
mkdir -p "$CONFIGDIR" "$WORKDIR/blobs" "$WORKDIR/source/pack-v1"
echo 'version-v1' >"$WORKDIR/source/pack-v1/image.raw"
echo 'version-v2' >"$WORKDIR/source/pack-v2"
(cd "$WORKDIR/source" && sha256sum pack-v1/image.raw pack-v2 >SHA256SUMS)
cat >"$CONFIGDIR/01-manifest-yes-and-retry.transfer" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=pack-@v/image.raw pack-@v

[Target]
Type=regular-file
Path=$WORKDIR/blobs
MatchPattern=pack-@v
InstancesMax=1
EOF
"$SYSUPDATE" --verify=no update
cmp "$WORKDIR/source/pack-v2" "$WORKDIR/blobs/pack-v2"
rm -rf "$CONFIGDIR/01-manifest-yes-and-retry.transfer" \
       "$WORKDIR/source/pack-v1" "$WORKDIR/source/pack-v2"

# Test that listing components/targets when none are configured gives an empty list.
"$SYSUPDATE" components |& grep "No components defined." >/dev/null
[[ $(varlinkctl call "$VARLINK_SOCKET" io.systemd.SysUpdate.ListTargets | jq -r '.targets') == "[]" ]]

# ============================================================================
# Components & features: enable/disable verbs, the --component-{all,suggested}
# and --feature-{all,suggested} switches, plus the Suggest=/SuggestOn…=
# settings. Everything below operates on freshly minted throw-away components
# and features, and cleans up after itself.
#
# Layout used throughout:
#   * a component <c> is defined by a transfer directory /run/sysupdate.<c>.d/
#     (which is what makes it show up in the 'components' list) plus an optional
#     metadata file /run/sysupdate.<c>.component carrying Description=/Suggest=/…
#   * the enable-component/disable-component verbs write their Enabled= override
#     into a drop-in below /etc/sysupdate.<c>.component.d/
#   * the enable-feature/disable-feature verbs write their Enabled= override into
#     a drop-in below /etc/sysupdate.d/<f>.feature.d/ (default component) or
#     /etc/sysupdate.<c>.d/<f>.feature.d/ (named component)
# ============================================================================
CF="$WORKDIR/compfeat"

# The Suggest…MachineTag= tests below drive the machine tags via /etc/machine-info
# (which the condition logic reads directly); back up any pre-existing file so we
# can restore it afterwards, mirroring TEST-74-AUX-UTILS.machine-tags.sh.
MI_BAK="$WORKDIR/machine-info.orig"
rm -f "$MI_BAK"
[[ -e /etc/machine-info ]] && cp -a /etc/machine-info "$MI_BAK"

set_machine_tags() {
    if [[ -n "${1:-}" ]]; then
        echo "TAGS=$1" >/etc/machine-info
    else
        rm -f /etc/machine-info
    fi
}

restore_machine_info() {
    if [[ -e "$MI_BAK" ]]; then
        cp -a "$MI_BAK" /etc/machine-info
    else
        rm -f /etc/machine-info
    fi
}

compfeat_cleanup() {
    rm -rf /run/sysupdate.d \
           /run/sysupdate.compx.d /run/sysupdate.compx.component /run/sysupdate.compx.component.d \
           /run/sysupdate.compy.d /run/sysupdate.compy.component /run/sysupdate.compy.component.d \
           /run/sysupdate.compz.d /run/sysupdate.compz.component /run/sysupdate.compz.component.d \
           /etc/sysupdate.d \
           /etc/sysupdate.compx.d /etc/sysupdate.compx.component.d \
           /etc/sysupdate.compy.d /etc/sysupdate.compy.component.d \
           /etc/sysupdate.compz.d /etc/sysupdate.compz.component.d
    rm -rf "$CF"
}

compfeat_reset() {
    compfeat_cleanup
    mkdir -p "$CF/source" \
             "$CF/target-default" "$CF/target-compx" "$CF/target-compy" "$CF/target-compz"
}

# (Re)generate the source payloads + SHA256SUMS for a given version. We create a
# payload for every component/feature so a single SHA256SUMS covers them all;
# individual transfers only ever match their own pattern.
compfeat_source() {
    local v="${1:?}"
    local n
    for n in base compx compy compz feata featb featc; do
        echo "$n-$v-$RANDOM" >"$CF/source/$n-$v.bin"
    done
    (cd "$CF/source" && sha256sum -- *.bin >SHA256SUMS)
}

# Write a regular-file transfer; optional 4th argument gates it behind a feature.
compfeat_transfer() {
    local file="${1:?}" pat="${2:?}" tgt="${3:?}" feature="${4:-}"
    {
        if [[ -n "$feature" ]]; then
            printf '[Transfer]\nFeatures=%s\n\n' "$feature"
        fi
        printf '[Source]\nType=regular-file\nPath=%s\nMatchPattern=%s-@v.bin\n\n' "$CF/source" "$pat"
        printf '[Target]\nType=regular-file\nPath=%s\nMatchPattern=%s-@v.bin\nInstancesMax=2\n' "$tgt" "$pat"
    } >"$file"
}

comp_enable_dropin()          { echo "/etc/sysupdate.$1.component.d/50-systemd-sysupdate-enabled.conf"; }
feat_enable_dropin_default()  { echo "/etc/sysupdate.d/$1.feature.d/50-systemd-sysupdate-enabled.conf"; }
feat_enable_dropin_comp()     { echo "/etc/sysupdate.$1.d/$2.feature.d/50-systemd-sysupdate-enabled.conf"; }

# Assert a generated Enabled= drop-in exists and carries the expected value.
assert_dropin() {
    local file="${1:?}" val="${2:?}"
    test -f "$file"
    grep "^Enabled=$val$" "$file" >/dev/null
}

# ---------------------------------------------------------------------------
# enable-component / disable-component: explicit selection + observable effect
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.compx.d
compfeat_transfer /run/sysupdate.compx.d/01-compx.transfer compx "$CF/target-compx"
# A metadata file carrying a human-readable description (exercises loading of the
# per-component *.component file from the search dirs).
cat >/run/sysupdate.compx.component <<EOF
[Component]
Description=CompXDescription
EOF

# The description from the *.component file must surface in the 'components' listing.
"$SYSUPDATE" --no-legend components | grep -F "CompXDescription" >/dev/null

# A brand new component (no Enabled= override anywhere) is enabled by default and
# can be updated.
"$SYSUPDATE" --component=compx --verify=no update
test -f "$CF/target-compx/compx-v1.bin"

# Disable it: this must drop an Enabled=no override next to the definition, and
# subsequent updates for that component must be refused.
"$SYSUPDATE" disable-component compx
assert_dropin "$(comp_enable_dropin compx)" no
(! "$SYSUPDATE" --component=compx --verify=no update) |& grep -F "Component is disabled" >/dev/null

# Re-enable via the "--component= + no positional argument" form and verify the
# update works again.
"$SYSUPDATE" --component=compx enable-component
assert_dropin "$(comp_enable_dropin compx)" yes
rm -f "$CF/target-compx/compx-v1.bin"
"$SYSUPDATE" --component=compx --verify=no update
test -f "$CF/target-compx/compx-v1.bin"

# Enabling a component must not conjure a bogus "<c>.component" pseudo-component
# out of the freshly created sysupdate.compx.component.d/ drop-in directory.
(! "$SYSUPDATE" --json=short components | grep -F '"compx.component"' >/dev/null)
"$SYSUPDATE" --json=short components | grep -F '"compx"' >/dev/null

# ---------------------------------------------------------------------------
# enable-component / disable-component: argument validation & error handling
# ---------------------------------------------------------------------------
# Positional argument and --component= are mutually exclusive.
(! "$SYSUPDATE" --component=compx enable-component compx) |& grep -F "not both" >/dev/null
# Syntactically invalid component name.
(! "$SYSUPDATE" enable-component ../nope) |& grep -F "Component name invalid" >/dev/null
# Unknown component.
(! "$SYSUPDATE" enable-component doesnotexist) |& grep -F "Component not found" >/dev/null
# --definitions= is incompatible with component enablement.
(! "$SYSUPDATE" --definitions="$CF" enable-component compx) |& grep -F "may not be combined" >/dev/null
# The feature-selection switches make no sense here.
(! "$SYSUPDATE" --feature-all enable-component compx) |& grep -F "not supported" >/dev/null

# ---------------------------------------------------------------------------
# --component-all for enable-component / disable-component
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.compx.d /run/sysupdate.compy.d
compfeat_transfer /run/sysupdate.compx.d/01-compx.transfer compx "$CF/target-compx"
compfeat_transfer /run/sysupdate.compy.d/01-compy.transfer compy "$CF/target-compy"

# Disable *all* components in one go, then re-enable them all.
"$SYSUPDATE" --component-all disable-component
assert_dropin "$(comp_enable_dropin compx)" no
assert_dropin "$(comp_enable_dropin compy)" no
(! "$SYSUPDATE" --component=compx --verify=no update) |& grep -F "Component is disabled" >/dev/null
(! "$SYSUPDATE" --component=compy --verify=no update) |& grep -F "Component is disabled" >/dev/null

"$SYSUPDATE" --component-all enable-component
assert_dropin "$(comp_enable_dropin compx)" yes
assert_dropin "$(comp_enable_dropin compy)" yes
"$SYSUPDATE" --component=compx --verify=no update
"$SYSUPDATE" --component=compy --verify=no update
test -f "$CF/target-compx/compx-v1.bin"
test -f "$CF/target-compy/compy-v1.bin"

# ---------------------------------------------------------------------------
# --component-suggested driven by Suggest= (compx suggested, compy not)
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.compx.d /run/sysupdate.compy.d
compfeat_transfer /run/sysupdate.compx.d/01-compx.transfer compx "$CF/target-compx"
compfeat_transfer /run/sysupdate.compy.d/01-compy.transfer compy "$CF/target-compy"
cat >/run/sysupdate.compx.component <<EOF
[Component]
Suggest=yes
EOF
cat >/run/sysupdate.compy.component <<EOF
[Component]
Suggest=no
EOF

# 'enable-component --component-suggested' acts on the suggested components only.
"$SYSUPDATE" --component-suggested enable-component
assert_dropin "$(comp_enable_dropin compx)" yes
test ! -e "$(comp_enable_dropin compy)"

# 'disable-component --component-suggested' reconciles the other way around: it
# acts on the components that are *not* suggested (i.e. compy).
"$SYSUPDATE" --component-suggested disable-component
assert_dropin "$(comp_enable_dropin compy)" no
# compx must be left as it was (still enabled from above).
assert_dropin "$(comp_enable_dropin compx)" yes

# --component-suggested is not supported for the update verb.
(! "$SYSUPDATE" --component-suggested --verify=no update) |& grep -F "not supported" >/dev/null

# ---------------------------------------------------------------------------
# SuggestOnMachineTag= for a component
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.compz.d
compfeat_transfer /run/sysupdate.compz.d/01-compz.transfer compz "$CF/target-compz"
cat >/run/sysupdate.compz.component <<EOF
[Component]
SuggestOnMachineTag=sysupdate-test-tag
EOF

# Without the matching machine tag the component is not suggested, so
# --component-suggested selects nothing.
set_machine_tags some-other-tag
"$SYSUPDATE" --component-suggested enable-component
test ! -e "$(comp_enable_dropin compz)"

# With the matching tag present it becomes suggested and gets enabled.
set_machine_tags sysupdate-test-tag:another
"$SYSUPDATE" --component-suggested enable-component
assert_dropin "$(comp_enable_dropin compz)" yes
set_machine_tags ""

# ---------------------------------------------------------------------------
# enable-feature / disable-feature on the default component + observable effect
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.d
compfeat_transfer /run/sysupdate.d/01-base.transfer base "$CF/target-default"
compfeat_transfer /run/sysupdate.d/50-feata.transfer feata "$CF/target-default" feata
cat >/run/sysupdate.d/feata.feature <<EOF
[Feature]
Description=Feature A
EOF

# The feature is listed and disabled by default, so its transfer is not installed.
"$SYSUPDATE" features | grep -F "feata" >/dev/null
"$SYSUPDATE" --verify=no update
test -f "$CF/target-default/base-v1.bin"
test ! -e "$CF/target-default/feata-v1.bin"

# Enabling the feature must drop an Enabled=yes override and cause the gated
# transfer to be installed on the next update.
"$SYSUPDATE" enable-feature feata
assert_dropin "$(feat_enable_dropin_default feata)" yes
"$SYSUPDATE" --verify=no update
test -f "$CF/target-default/feata-v1.bin"

# Disabling it again + vacuum must remove the now-orphaned feature resource.
"$SYSUPDATE" disable-feature feata
assert_dropin "$(feat_enable_dropin_default feata)" no
"$SYSUPDATE" --verify=no vacuum
test ! -e "$CF/target-default/feata-v1.bin"

# Argument validation for the feature verbs.
(! "$SYSUPDATE" enable-feature --feature-all feata) |& grep -F "not both" >/dev/null
(! "$SYSUPDATE" enable-feature 'bad/name') |& grep -F "Feature name invalid" >/dev/null
(! "$SYSUPDATE" --component-suggested enable-feature feata) |& grep -F "not supported" >/dev/null

# ---------------------------------------------------------------------------
# --feature-all / --feature-suggested (default component)
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.d
compfeat_transfer /run/sysupdate.d/01-base.transfer base "$CF/target-default"
# feata: suggested (Suggest=yes); featb: not suggested (Suggest=no);
# featc: suggested on a machine tag we will set below.
cat >/run/sysupdate.d/feata.feature <<EOF
[Feature]
Suggest=yes
EOF
cat >/run/sysupdate.d/featb.feature <<EOF
[Feature]
Suggest=no
EOF
cat >/run/sysupdate.d/featc.feature <<EOF
[Feature]
SuggestOnMachineTag=sysupdate-test-tag
EOF

# --feature-all operates on every known feature.
"$SYSUPDATE" enable-feature --feature-all
assert_dropin "$(feat_enable_dropin_default feata)" yes
assert_dropin "$(feat_enable_dropin_default featb)" yes
assert_dropin "$(feat_enable_dropin_default featc)" yes

# --feature-suggested (no machine tag): only the Suggest=yes feature is picked.
rm -rf /etc/sysupdate.d
set_machine_tags unrelated
"$SYSUPDATE" enable-feature --feature-suggested
assert_dropin "$(feat_enable_dropin_default feata)" yes
test ! -e "$(feat_enable_dropin_default featb)"
test ! -e "$(feat_enable_dropin_default featc)"

# --feature-suggested with the machine tag set: feata + featc are picked.
rm -rf /etc/sysupdate.d
set_machine_tags sysupdate-test-tag
"$SYSUPDATE" enable-feature --feature-suggested
assert_dropin "$(feat_enable_dropin_default feata)" yes
assert_dropin "$(feat_enable_dropin_default featc)" yes
test ! -e "$(feat_enable_dropin_default featb)"
set_machine_tags ""

# ---------------------------------------------------------------------------
# Features scoped to a named component, and across all components at once
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.d /run/sysupdate.compx.d
compfeat_transfer /run/sysupdate.d/01-base.transfer base "$CF/target-default"
compfeat_transfer /run/sysupdate.compx.d/01-compx.transfer compx "$CF/target-compx"
cat >/run/sysupdate.d/feata.feature <<EOF
[Feature]
Description=Default feature A
EOF
cat >/run/sysupdate.compx.d/featx.feature <<EOF
[Feature]
Description=Component X feature
EOF

# --component= scopes feature operations to that component: the drop-in must land
# next to the component's definitions, and the default component is untouched.
"$SYSUPDATE" --component=compx enable-feature --feature-all
assert_dropin "$(feat_enable_dropin_comp compx featx)" yes
test ! -e "$(feat_enable_dropin_default feata)"

# --component-all --feature-all fans out over the default component *and* every
# named component.
rm -rf /etc/sysupdate.d /etc/sysupdate.compx.d
"$SYSUPDATE" --component-all enable-feature --feature-all
assert_dropin "$(feat_enable_dropin_default feata)" yes
assert_dropin "$(feat_enable_dropin_comp compx featx)" yes

# ---------------------------------------------------------------------------
# update --component-all installs every component's update in one invocation
# ---------------------------------------------------------------------------
compfeat_reset
compfeat_source v1
mkdir -p /run/sysupdate.compx.d /run/sysupdate.compy.d
compfeat_transfer /run/sysupdate.compx.d/01-compx.transfer compx "$CF/target-compx"
compfeat_transfer /run/sysupdate.compy.d/01-compy.transfer compy "$CF/target-compy"

"$SYSUPDATE" --component-all --verify=no update
test -f "$CF/target-compx/compx-v1.bin"
test -f "$CF/target-compy/compy-v1.bin"

# A second version must likewise be rolled out to every component at once.
compfeat_source v2
"$SYSUPDATE" --component-all --verify=no update
test -f "$CF/target-compx/compx-v2.bin"
test -f "$CF/target-compy/compy-v2.bin"

# A disabled component must not turn "update --component-all" into a failure:
# it is skipped, while the remaining enabled components are still updated.
"$SYSUPDATE" disable-component compy
compfeat_source v3
"$SYSUPDATE" --component-all --verify=no update
test -f "$CF/target-compx/compx-v3.bin"
test ! -e "$CF/target-compy/compy-v3.bin"

compfeat_cleanup
restore_machine_info

touch /testok
