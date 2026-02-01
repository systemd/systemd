#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ ! -f /usr/lib/systemd/system/systemd-mountfsd.socket ]] ||
   [[ ! -f /usr/lib/systemd/system/systemd-nsresourced.socket ]] ||
   ! command -v mksquashfs ||
   ! grep -q bpf /sys/kernel/security/lsm ||
   ! find /usr/lib* -name libbpf.so.1 2>/dev/null | grep . ||
   systemd-analyze compare-versions "$(uname -r)" lt 6.5 ||
   systemd-analyze compare-versions "$(pkcheck --version | awk '{print $3}')" lt 124; then
    echo "Skipping mountfsd/nsresourced tests"
    exit 0
fi

at_exit() {
    set +e

    umount -R /tmp/unpriv/mount
    rmdir /tmp/unpriv
    rm -f /tmp/test-50-unpriv-privkey.key /tmp/test-50-unpriv-cert.crt /run/verity.d/test-50-unpriv-cert.crt
    rm -f /var/tmp/unpriv.raw /tmp/unpriv.raw.mtree /tmp/unpriv2.raw.mtree
    rm -f /tmp/unpriv.out /tmp/unpriv.out2 /tmp/unpriv.out3
}

trap at_exit EXIT

systemctl start systemd-mountfsd.socket systemd-nsresourced.socket

openssl req -config "$OPENSSL_CONFIG" -subj="/CN=waldo" \
            -x509 -sha256 -nodes -days 365 -newkey rsa:4096 \
            -keyout /tmp/test-50-unpriv-privkey.key -out /tmp/test-50-unpriv-cert.crt

systemd-dissect --mkdir --mount "$MINIMAL_IMAGE.raw" /tmp/unpriv/mount
SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs \
    systemd-repart -P \
                   -s /tmp/unpriv/mount \
                   --certificate=/tmp/test-50-unpriv-cert.crt \
                   --private-key=/tmp/test-50-unpriv-privkey.key \
                   /var/tmp/unpriv.raw
systemd-dissect --rmdir --umount /tmp/unpriv/mount

systemd-dissect --image-policy='root=unprotected:=absent+unused' /var/tmp/unpriv.raw
systemd-dissect --image-policy='root=unprotected:=absent+unused' --mtree /var/tmp/unpriv.raw >/tmp/unpriv.raw.mtree

# Run unpriv, should fail due to lack of privs
(! runas testuser systemd-dissect /var/tmp/unpriv.raw)
(! runas testuser systemd-dissect --mtree /var/tmp/unpriv.raw)

if (SYSTEMD_LOG_TARGET=console varlinkctl call \
        /run/systemd/userdb/io.systemd.NamespaceResource \
        io.systemd.NamespaceResource.AllocateUserRange \
        '{"name":"test-supported","size":65536,"userNamespaceFileDescriptor":0}' 2>&1 || true) |
            grep "io.systemd.NamespaceResource.UserNamespaceInterfaceNotSupported" >/dev/null; then
    echo "User namespace interface not supported, skipping mountfsd/nsresourced tests"
    exit 0
fi

# This should work without the key
systemd-dissect --image-policy='root=verity:=absent+unused' --mtree /var/tmp/unpriv.raw >/dev/null
systemd-dissect --image-policy='root=verity+signed:=absent+unused' --mtree /var/tmp/unpriv.raw >/dev/null

# This should fail before we install the key
(! systemd-dissect --image-policy='root=signed:=absent+unused' --mtree /var/tmp/unpriv.raw >/dev/null)

# If the kernel support is present unprivileged user units should be able to use verity images too
if [ "$VERITY_SIG_SUPPORTED" -eq 1 ]; then
    systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.gpt" \
        test -e "/dev/mapper/${MINIMAL_IMAGE_ROOTHASH}-verity"

    systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.raw" \
        --property ExtensionImages=/tmp/app0.raw \
        bash -c "test -e \"/dev/mapper/${MINIMAL_IMAGE_ROOTHASH}-verity\" && test -e \"/dev/mapper/$(</tmp/app0.roothash)-verity\""

    # Without a signature this should not work, as mountfsd should reject it, even if we explicitly ask to
    # trust it
    mv /tmp/app0.roothash.p7s /tmp/app0.roothash.p7s.bak
    (! systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.raw" \
        --property ExtensionImages=/tmp/app0.raw \
        bash -c "test -e \"/dev/mapper/${MINIMAL_IMAGE_ROOTHASH}-verity\" && test -e \"/dev/mapper/$(</tmp/app0.roothash)-verity\"")
    (! systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.raw" \
        --property ExtensionImages=/tmp/app0.raw \
        --property ExtensionImagePolicy=root=verity+signed+absent:usr=verity+signed+absent \
        bash -c "test -e \"/dev/mapper/${MINIMAL_IMAGE_ROOTHASH}-verity\" && test -e \"/dev/mapper/$(</tmp/app0.roothash)-verity\"")
    mv /tmp/app0.roothash.p7s.bak /tmp/app0.roothash.p7s

    # Mount options should not be allowed without elevated privileges
    (! systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.gpt" \
        --property RootImageOptions="root:ro,noatime,nosuid home:ro,dev nosuid,dev" \
        --property RootImageOptions="home:ro,dev nosuid,dev,%%foo" \
        true)
    (! systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.raw" \
        --property ExtensionImages=/tmp/app0.raw \
        --property MountImages=/tmp/app0.raw:/var/tmp:noatime,nosuid \
        true)

    mkdir -p /etc/polkit-1/rules.d
    cat >/etc/polkit-1/rules.d/mountoptions.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "io.systemd.mount-file-system.mount-untrusted-image-privately" &&
            action.lookup("mount_options") == "root:nosuid") {
        return polkit.Result.YES;
    }
});
EOF
    systemctl try-reload-or-restart polkit.service

    systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.gpt" \
        --property RootImageOptions="root:nosuid" \
        sh -c "test -e \"/dev/mapper/${MINIMAL_IMAGE_ROOTHASH}-verity\" && mount | grep -F squashfs | grep -q -F nosuid"

    systemd-run -M testuser@ --user --pipe --wait \
        --property RootImage="$MINIMAL_IMAGE.raw" \
        --property ExtensionImages=/tmp/app0.raw \
        --property MountImages=/tmp/app0.raw:/var/tmp:nosuid \
        sh -c "test -e \"/dev/mapper/${MINIMAL_IMAGE_ROOTHASH}-verity\" && test -e \"/dev/mapper/$(</tmp/app0.roothash)-verity\" && mount | grep -F /var/tmp | grep -q -F nosuid"

    rm -f /etc/polkit-1/rules.d/mountoptions.rules
    systemctl try-reload-or-restart polkit.service
fi

# Bare squashfs without any verity or signature also should be rejected, even if we ask to trust it
(! systemd-run -M testuser@ --user --pipe --wait \
    --property ExtensionImages=/tmp/app1.raw \
    true)
(! systemd-run -M testuser@ --user --pipe --wait \
    --property ExtensionImages=/tmp/app1.raw \
    --property ExtensionImagePolicy=root=verity+signed+unprotected+absent:usr=verity+signed+unprotected+absent \
    true)

# Install key in keychain
mkdir -p /run/verity.d
cp /tmp/test-50-unpriv-cert.crt /run/verity.d/

# This should work now
systemd-dissect --image-policy='root=signed:=absent+unused' --mtree /var/tmp/unpriv.raw >/dev/null

# This should still work
systemd-dissect --image-policy='root=verity:=absent+unused' --mtree /var/tmp/unpriv.raw >/dev/null
systemd-dissect --image-policy='root=verity+signed:=absent+unused' --mtree /var/tmp/unpriv.raw >/dev/null

# Now run unpriv again, should be OK now.
runas testuser systemd-dissect /var/tmp/unpriv.raw
runas testuser systemd-dissect --mtree /var/tmp/unpriv.raw >/tmp/unpriv2.raw.mtree

# Check that unpriv and priv run yielded same results
cmp /tmp/unpriv.raw.mtree /tmp/unpriv2.raw.mtree

# Make sure nspawn works unpriv, too (for now do not nest)
if ! systemd-detect-virt -c; then
    systemd-nspawn --pipe -i /var/tmp/unpriv.raw --read-only echo thisisatest >/tmp/unpriv.out
    echo thisisatest | cmp /tmp/unpriv.out -

    # The unpriv user has no rights to lock the image or write to it. Let's
    # turn off both for this test, so that we don't have to copy the image
    # around.
    systemd-run -M testuser@ --user --pipe \
                -p Environment=SYSTEMD_NSPAWN_LOCK=0 \
                -p Delegate=1 \
                -p DelegateSubgroup=supervisor \
                -p Environment=SYSTEMD_LOG_LEVEL=debug \
                --wait -- \
                systemd-nspawn --keep-unit --register=no -i /var/tmp/unpriv.raw --read-only --pipe echo thisisatest >/tmp/unpriv.out2
    echo thisisatest | cmp /tmp/unpriv.out2 -
fi

systemd-run -M testuser@ --user --pipe -p RootImage=/var/tmp/unpriv.raw -p PrivateUsers=1 --wait echo thisisatest >/tmp/unpriv.out3
echo thisisatest | cmp /tmp/unpriv.out3 -

# make sure MakeDirectory() works correctly
assert_eq "$(run0 -u testuser varlinkctl --exec call  /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.MakeDirectory --push-fd=./ '{ "parentFileDescriptor" : 0, "name" : "foreignuidowned" }' -- stat -Lc "%u" /proc/self/fd/3)" 2147352576
assert_eq "$(stat -c "%u" ~testuser/foreignuidowned)" 2147352576
rmdir ~testuser/foreignuidowned

# make sure ChownDirectory() works correctly
TESTHOME=~testuser
mkdir -p "$TESTHOME/chowntest/subdir"
touch "$TESTHOME/chowntest/subdir/file"
chown -R testuser:testuser "$TESTHOME/chowntest"

# Run ChownDirectory as testuser - should chown to FOREIGN_UID_MIN (2147352576)
run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.ChownDirectory --push-fd="$TESTHOME/chowntest" '{ "directoryFileDescriptor" : 0 }'

# Verify everything is now owned by FOREIGN_UID_MIN
assert_eq "$(stat -c "%u" "$TESTHOME/chowntest")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/chowntest/subdir")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/chowntest/subdir/file")" 2147352576

rm -rf "$TESTHOME/chowntest"

# Test that ChownDirectory only changes inodes owned by peer
mkdir "$TESTHOME/chowntest2"
chown testuser:testuser "$TESTHOME/chowntest2"
mkdir "$TESTHOME/chowntest2/mine"
chown testuser:testuser "$TESTHOME/chowntest2/mine"
mkdir "$TESTHOME/chowntest2/notmine"

# ChownDirectory should only chown things owned by testuser, not root's directory
run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.ChownDirectory --push-fd="$TESTHOME/chowntest2" '{ "directoryFileDescriptor" : 0 }'

# testuser's directories should be chowned
assert_eq "$(stat -c "%u" "$TESTHOME/chowntest2")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/chowntest2/mine")" 2147352576
# root's directory should remain unchanged
assert_eq "$(stat -c "%u" "$TESTHOME/chowntest2/notmine")" 0

rm -rf "$TESTHOME/chowntest2"

# make sure RemoveDirectory() works correctly
# First create a directory tree owned by the foreign UID range
run0 -u testuser varlinkctl --exec call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.MakeDirectory --push-fd="$TESTHOME" '{ "parentFileDescriptor" : 0, "name" : "removeme" }' -- true
assert_eq "$(stat -c "%u" "$TESTHOME/removeme")" 2147352576

# Create some content inside it, also owned by foreign UID range
mkdir "$TESTHOME/removeme/subdir"
touch "$TESTHOME/removeme/subdir/file"
chown -R 2147352576:2147352576 "$TESTHOME/removeme"

# Remove it using RemoveDirectory
run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.RemoveDirectory --push-fd="$TESTHOME" '{ "parentFileDescriptor" : 0, "name" : "removeme" }'

# Verify it's gone
test ! -e "$TESTHOME/removeme"

# Test that RemoveDirectory only removes inodes owned by foreign UID range
mkdir "$TESTHOME/removeme2"
chown 2147352576:2147352576 "$TESTHOME/removeme2"
mkdir "$TESTHOME/removeme2/foreign"
chown 2147352576:2147352576 "$TESTHOME/removeme2/foreign"
mkdir "$TESTHOME/removeme2/notforeign"
chown root:root "$TESTHOME/removeme2/notforeign"

# RemoveDirectory should fail because there's content not owned by foreign UID range
(! run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.RemoveDirectory --push-fd="$TESTHOME" '{ "parentFileDescriptor" : 0, "name" : "removeme2" }')

# The directory should still exist with the root-owned content
test -d "$TESTHOME/removeme2"
test -d "$TESTHOME/removeme2/notforeign"

rm -rf "$TESTHOME/removeme2"

# Make sure CopyDirectory() works correctly
mkdir -p "$TESTHOME/copysource/subdir"
echo "hello" > "$TESTHOME/copysource/file.txt"
echo "world" > "$TESTHOME/copysource/subdir/nested.txt"
chown -R 2147352576:2147352576 "$TESTHOME/copysource"

# Copy it using CopyDirectory - destination should preserve foreign UID range ownership
run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.CopyDirectory --push-fd="$TESTHOME/copysource" --push-fd="$TESTHOME" '{ "sourceFileDescriptor" : 0, "destinationParentFileDescriptor" : 1, "name" : "copydest" }'

# Verify the copy exists and is owned by the foreign UID root user
test -d "$TESTHOME/copydest"
assert_eq "$(stat -c "%u" "$TESTHOME/copydest")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/copydest/subdir")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/copydest/file.txt")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/copydest/subdir/nested.txt")" 2147352576

# Verify content was actually copied
assert_eq "$(cat "$TESTHOME/copydest/file.txt")" "hello"
assert_eq "$(cat "$TESTHOME/copydest/subdir/nested.txt")" "world"

rm -rf "$TESTHOME/copysource" "$TESTHOME/copydest"

# Test that CopyDirectory fails if source inodes are outside the foreign UID range
mkdir -p "$TESTHOME/copysource2/foreign"
mkdir "$TESTHOME/copysource2/notforeign"
echo "foreign" > "$TESTHOME/copysource2/foreign/file.txt"
echo "notforeign" > "$TESTHOME/copysource2/notforeign/file.txt"
chown -R 2147352576:2147352576 "$TESTHOME/copysource2"
chown -R root:root "$TESTHOME/copysource2/notforeign"

(! run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.CopyDirectory --push-fd="$TESTHOME/copysource2" --push-fd="$TESTHOME" '{ "sourceFileDescriptor" : 0, "destinationParentFileDescriptor" : 1, "name" : "copydest2" }')

test ! -d "$TESTHOME/copydest2"
rm -rf "$TESTHOME/copysource2"

# Make sure RenameDirectory() works correctly
mkdir -p "$TESTHOME/renamesource/subdir"
echo "hello" > "$TESTHOME/renamesource/file.txt"
echo "world" > "$TESTHOME/renamesource/subdir/nested.txt"
chown -R 2147352576:2147352576 "$TESTHOME/renamesource"

# Rename it using RenameDirectory
run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.RenameDirectory --push-fd="$TESTHOME" --push-fd="$TESTHOME" '{ "sourceParentFileDescriptor" : 0, "sourceName" : "renamesource", "destinationParentFileDescriptor" : 1, "destinationName" : "renamedest" }'

# Verify the rename worked
test ! -d "$TESTHOME/renamesource"
test -d "$TESTHOME/renamedest"
assert_eq "$(stat -c "%u" "$TESTHOME/renamedest")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/renamedest/subdir")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/renamedest/file.txt")" 2147352576
assert_eq "$(stat -c "%u" "$TESTHOME/renamedest/subdir/nested.txt")" 2147352576

# Verify content is still there
assert_eq "$(cat "$TESTHOME/renamedest/file.txt")" "hello"
assert_eq "$(cat "$TESTHOME/renamedest/subdir/nested.txt")" "world"

rm -rf "$TESTHOME/renamedest"

# Test that RenameDirectory fails if source directory is not owned by the foreign UID range
mkdir "$TESTHOME/renamesource2"
chown root:root "$TESTHOME/renamesource2"

(! run0 -u testuser varlinkctl call /run/systemd/io.systemd.MountFileSystem io.systemd.MountFileSystem.RenameDirectory --push-fd="$TESTHOME" --push-fd="$TESTHOME" '{ "sourceParentFileDescriptor" : 0, "sourceName" : "renamesource2", "destinationParentFileDescriptor" : 1, "destinationName" : "renamedest2" }')

# The directory should still exist in the original location
test -d "$TESTHOME/renamesource2"
test ! -d "$TESTHOME/renamedest2"

rm -rf "$TESTHOME/renamesource2"
