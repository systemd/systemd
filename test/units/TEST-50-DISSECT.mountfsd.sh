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

# Test delegated UID ranges
# Verify that delegated ranges show up in uid_map (6 lines: 1 primary + 2 container ranges + 3 dynamic users)
test "$(run0 -u testuser --pipe unshare --user varlinkctl --exec call \
        --push-fd=/proc/self/ns/user \
        /run/systemd/userdb/io.systemd.NamespaceResource \
        io.systemd.NamespaceResource.AllocateUserRange \
        '{"name":"test-delegate","size":65536,"userNamespaceFileDescriptor":0,"delegateContainerRanges":2}' \
        -- cat /proc/self/uid_map | wc -l)" -eq 3

# Test that delegateContainerRanges > 16 fails with TooManyDelegations error
(! run0 -u testuser --pipe unshare --user varlinkctl call \
        --push-fd=/proc/self/ns/user \
        /run/systemd/userdb/io.systemd.NamespaceResource \
        io.systemd.NamespaceResource.AllocateUserRange \
        '{"name":"test-fail","size":65536,"userNamespaceFileDescriptor":0,"delegateContainerRanges":17}') |&
            grep "io.systemd.NamespaceResource.TooManyDelegations" >/dev/null

# Test self mapping
# Verify that self mapping maps the peer UID to root (uid_map should show "0 <peer_uid> 1")
test "$(run0 -u testuser --pipe unshare --user varlinkctl --exec call \
        --push-fd=/proc/self/ns/user \
        /run/systemd/userdb/io.systemd.NamespaceResource \
        io.systemd.NamespaceResource.AllocateUserRange \
        '{"name":"test-id","target":0,"size":1,"userNamespaceFileDescriptor":0,"type":"self"}' \
        -- cat /proc/self/uid_map | awk '{print $1, $3}')" = "0 1"

# Test nested delegation with self mapping
test "$(run0 -u testuser --pipe unshare --user varlinkctl --exec call \
        --push-fd=/proc/self/ns/user \
        /run/systemd/userdb/io.systemd.NamespaceResource \
        io.systemd.NamespaceResource.AllocateUserRange \
        '{"name":"test-delegate2","type":"self","size":1,"userNamespaceFileDescriptor":0,"delegateContainerRanges":3}' \
        -- unshare --user varlinkctl --exec call \
            --push-fd=/proc/self/ns/user \
            /run/systemd/userdb/io.systemd.NamespaceResource \
            io.systemd.NamespaceResource.AllocateUserRange \
            '{"name":"test-delegate3","size":65536,"userNamespaceFileDescriptor":0,"delegateContainerRanges":2}' \
            -- cat /proc/self/uid_map | wc -l)" -eq 3

# Test mapForeign parameter
# Verify that the foreign UID range is mapped into the user namespace
# When mapForeign is true, uid_map should have 2 lines: primary range + foreign range
test "$(run0 -u testuser --pipe unshare --user varlinkctl --exec call \
        --push-fd=/proc/self/ns/user \
        /run/systemd/userdb/io.systemd.NamespaceResource \
        io.systemd.NamespaceResource.AllocateUserRange \
        '{"name":"test-foreign","size":65536,"userNamespaceFileDescriptor":0,"mapForeign":true}' \
        -- cat /proc/self/uid_map | wc -l)" -eq 2

# Verify the foreign range is mapped 1:1.
test "$(run0 -u testuser --pipe unshare --user varlinkctl --exec call \
        --push-fd=/proc/self/ns/user \
        /run/systemd/userdb/io.systemd.NamespaceResource \
        io.systemd.NamespaceResource.AllocateUserRange \
        '{"name":"test-foreign2","size":65536,"userNamespaceFileDescriptor":0,"mapForeign":true}' \
        -- cat /proc/self/uid_map | grep -c 2147352576)" -eq 1

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
