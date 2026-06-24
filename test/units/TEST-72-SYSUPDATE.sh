#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

SYSUPDATE=/usr/bin/systemd-sysupdate
SYSUPDATED=/lib/systemd/systemd-sysupdated
UPDATECTL=""
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

update_now() {
    local update_type="${1:?}"
    local checks="${2:-}"

    # Update to newest version. First there should be an update ready, then we
    # do the update, and then there should not be any ready anymore
    #
    # The update can either be done monolithically (by calling the `update`
    # verb) or split (`acquire` then `update`). Both options are allowed for
    # most updates in the test suite, so the test suite can be run to test both
    # modes. Some updates in the test suite need to be monolithic (e.g. when
    # repairing an installation), so that can be overridden via the local.

    if [[ "$checks" != "no-checks" ]]; then
        "$SYSUPDATE" --verify=no check-new
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
        (! "$SYSUPDATE" --verify=no check-new)
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

    [[ "${updatectl_output}" != *"Unrecognized object field"* ]] || exit 1
}

for sector_size in "${SECTOR_SIZES[@]}"; do
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
    update_now "$update_type"
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
    if [[ -x "$UPDATECTL" ]]; then
        systemctl start systemd-sysupdated
        "$SYSUPDATE" --verify=no check-new
        "$UPDATECTL" update |& tee "$WORKDIR"/updatectl-update-6
        grep "Done" "$WORKDIR"/updatectl-update-6
        (! grep "Already up-to-date" "$WORKDIR"/updatectl-update-6)
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

    # Create a 9th version but corrupt the checksum in SHA256SUMS so pulling it
    # fails when verifying the checksum, in order to create a current+partial
    # state. Try to update again and verify that this results in an error.
    # Vacuum the partial version, regenerate it on the server, try updating
    # again and it should succeed.
    new_version "$sector_size" v9 "corrupt-checksum"
    (! update_now "$update_type")
    "$SYSUPDATE" --offline list v9 | grep "partial" >/dev/null
    verify_version_current "$blockdev" "$sector_size" v8 1
    # don’t verify the other part of the block device as it’s in an indeterminate state
    (! update_now "$update_type" "no-checks") |& tee "$WORKDIR"/update_now-9
    cat "$WORKDIR"/update_now-9
    grep "is already acquired and partially installed. Vacuum it to try installing again." "$WORKDIR"/update_now-9
    "$SYSUPDATE" --offline vacuum |& grep "Removing old partial" >/dev/null
    verify_version_current "$blockdev" "$sector_size" v8 1
    # don’t verify the other part of the block device as it’s in an indeterminate state
    "$SYSUPDATE" --verify=no list v9 | grep "candidate" >/dev/null
    new_version "$sector_size" v9
    update_now "$update_type"
    verify_version "$blockdev" "$sector_size" v8 1
    verify_version_current "$blockdev" "$sector_size" v9 2

    # Cleanup
    [[ -b "$blockdev" ]] && losetup --detach "$blockdev"
    rm "$BACKING_FILE"
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
mkdir /run/sysupdate.d
"$SYSUPDATE" --json=short components | grep -F '{"default":false,"components":["some-component"]}' >/dev/null

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

# --component-all is only supported for the "cleanup" verb, refuse it elsewhere.
(! "$SYSUPDATE" --component-all --verify=no update)

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

touch /testok
