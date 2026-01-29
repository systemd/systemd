#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

SYSUPDATE=/lib/systemd/systemd-sysupdate
SYSUPDATED=/lib/systemd/systemd-sysupdated
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

# Loopback devices may not be supported. They are used because sfdisk cannot
# change the sector size of a file, and we want to test both 512 and 4096 byte
# sectors. If loopback devices are not supported, we can only test one sector
# size, and the underlying device is likely to have a sector size of 512 bytes.
if [[ ! -e /dev/loop-control ]]; then
    echo "No loopback device support"
    SECTOR_SIZES=(512)
fi

# Set up sysupdated drop-in pointing at the correct definitions and setting
# no verification of images.
mkdir -p /run/systemd/system/systemd-sysupdated.service.d
cat >/run/systemd/system/systemd-sysupdated.service.d/override.conf<<EOF
[Service]
Environment=SYSTEMD_SYSUPDATE_NO_VERIFY=1
Environment=SYSTEMD_ESP_PATH=${SYSTEMD_ESP_PATH}
Environment=SYSTEMD_XBOOTLDR_PATH=${SYSTEMD_XBOOTLDR_PATH}
EOF
systemctl daemon-reload

at_exit() {
    set +e

    losetup -n --output NAME --associated "$BACKING_FILE" | while read -r loop_dev; do
        losetup --detach "$loop_dev"
    done

    rm -rf "$WORKDIR"
}

trap at_exit EXIT

update_checksums() {
    (cd "$WORKDIR/source" && rm -f BEST-BEFORE-* && sha256sum uki* part* dir-*.tar.gz >SHA256SUMS)
}

update_checksums_with_best_before() {
    (cd "$WORKDIR/source" && rm -f BEST-BEFORE-* && touch "BEST-BEFORE-$1" && sha256sum uki* part* dir-*.tar.gz "BEST-BEFORE-$1" >SHA256SUMS)
}

new_version() {
    local sector_size="${1:?}"
    local version="${2:?}"

    # Create a pair of random partition payloads, and compress one.
    # To make not the initial bytes of part1-xxx.raw accidentally match one of the compression header,
    # let's make the first sector filled by zero.
    dd if=/dev/zero of="$WORKDIR/source/part1-$version.raw" bs="$sector_size" count=1
    dd if=/dev/urandom of="$WORKDIR/source/part1-$version.raw" bs="$sector_size" count=2047 conv=notrunc oflag=append
    dd if=/dev/urandom of="$WORKDIR/source/part2-$version.raw" bs="$sector_size" count=2048
    gzip -k -f "$WORKDIR/source/part2-$version.raw"

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

    update_checksums
}

update_now() {
    local update_type="${1:?}"

    # Update to newest version. First there should be an update ready, then we
    # do the update, and then there should not be any ready anymore
    #
    # The update can either be done monolithically (by calling the `update`
    # verb) or split (`acquire` then `update`). Both options are allowed for
    # most updates in the test suite, so the test suite can be run to test both
    # modes. Some updates in the test suite need to be monolithic (e.g. when
    # repairing an installation), so that can be overridden via the local.

    "$SYSUPDATE" --verify=no check-new
    if [[ "$update_type" == "monolithic" ]]; then
        "$SYSUPDATE" --verify=no update
    elif [[ "$update_type" == "split-offline" ]]; then
        "$SYSUPDATE" --verify=no acquire
        "$SYSUPDATE" --verify=no update --offline
    elif [[ "$update_type" == "split" ]]; then
        "$SYSUPDATE" --verify=no acquire
        "$SYSUPDATE" --verify=no update
    fi
    (! "$SYSUPDATE" --verify=no check-new)
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
}

verify_version_current() {
    local version="${3:?}"

    verify_version "$@"

    # Check the directories
    cmp "$WORKDIR/source/dir-$version/foo.txt" "$WORKDIR/dirs/current/foo.txt"
    cmp "$WORKDIR/source/dir-$version/bar.txt" "$WORKDIR/dirs/current/bar.txt"
}

for sector_size in "${SECTOR_SIZES[@]}"; do
for update_type in monolithic split-offline split; do
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
MatchPattern=part2-@v
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

    rm -rf "${WORKDIR:?}"/{esp,xbootldr,source}
    mkdir -p "$WORKDIR"/{source,esp/EFI/Linux,xbootldr/EFI/Linux}

    # Install initial version and verify
    new_version "$sector_size" v1
    update_now "$update_type"
    verify_version_current "$blockdev" "$sector_size" v1 1

    # Create second version, update and verify that it is added
    new_version "$sector_size" v2
    update_now "$update_type"
    verify_version "$blockdev" "$sector_size" v1 1
    verify_version_current "$blockdev" "$sector_size" v2 2

    # Create third version, update and verify it replaced the first version
    new_version "$sector_size" v3
    update_now "$update_type"
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
    (! "$SYSUPDATE" --verify=no check-new)

    # Create a fifth version, that's complete on the server side. We should
    # completely skip the incomplete v4 and install v5 instead.
    new_version "$sector_size" v5
    update_now "$update_type"
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2

    # Make the local installation of v5 incomplete by deleting a file, then make
    # sure that sysupdate still recognizes the installation and can complete it
    # in place
    # Always do this as a monolithic update for the repair to work.
    rm -r "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d"
    "$SYSUPDATE" --offline list v5 | grep "incomplete" >/dev/null
    update_now "monolithic"
    "$SYSUPDATE" --offline list v5 | grep -v "incomplete" >/dev/null
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2

    # Now let's try enabling an optional feature
    "$SYSUPDATE" features | grep "optional"
    "$SYSUPDATE" features optional | grep "99-optional"
    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d/optional.efi"
    mkdir "$CONFIGDIR/optional.feature.d"
    echo -e "[Feature]\nEnabled=true" > "$CONFIGDIR/optional.feature.d/enable.conf"
    "$SYSUPDATE" --offline list v5 | grep "incomplete" >/dev/null
    update_now "monolithic"
    "$SYSUPDATE" --offline list v5 | grep -v "incomplete" >/dev/null
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2
    test -f "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d/optional.efi"

    # And now let's disable it and make sure it gets cleaned up
    rm -r "$CONFIGDIR/optional.feature.d"
    (! "$SYSUPDATE" --verify=no check-new)
    "$SYSUPDATE" vacuum
    "$SYSUPDATE" --offline list v5 | grep -v "incomplete" >/dev/null
    verify_version "$blockdev" "$sector_size" v3 1
    verify_version_current "$blockdev" "$sector_size" v5 2
    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v5.efi.extra.d/optional.efi"

    # Create sixth version, update using updatectl and verify it replaced the
    # correct version
    new_version "$sector_size" v6
    if [[ -x "$SYSUPDATED" ]] && command -v updatectl; then
        systemctl start systemd-sysupdated
        "$SYSUPDATE" --verify=no check-new
        updatectl update
    else
        # If no updatectl, gracefully fall back to systemd-sysupdate
        update_now "$update_type"
    fi
    # User-facing updatectl returns 0 if there's no updates, so use the low-level
    # utility to make sure we did upgrade
    (! "$SYSUPDATE" --verify=no check-new )
    verify_version_current "$blockdev" "$sector_size" v6 1
    verify_version "$blockdev" "$sector_size" v5 2

    # Next, let's run updatectl's various inspection commands. We're not
    # testing for specific output, but this will at least catch obvious crashes
    # and allow updatectl to run under the various sanitizers. We create a
    # component so that updatectl has multiple targets to list.
    if [[ -x "$SYSUPDATED" ]] && command -v updatectl; then
        mkdir -p /run/sysupdate.test.d/
        cp "$CONFIGDIR/01-first.transfer" /run/sysupdate.test.d/01-first.transfer
        updatectl list
        updatectl list host
        updatectl list host@v6
        updatectl check
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
MatchPattern=part2-@v
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

    update_now "$update_type"
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
    update_now "$update_type"
    verify_version_current "$blockdev" "$sector_size" v8 1
    verify_version "$blockdev" "$sector_size" v7 2

    # Cleanup
    [[ -b "$blockdev" ]] && losetup --detach "$blockdev"
    rm "$BACKING_FILE"
done
done

touch /testok
