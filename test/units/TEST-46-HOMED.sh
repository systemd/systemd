#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016,SC2209
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Check if homectl is installed, and if it isn't bail out early instead of failing
if ! command -v homectl >/dev/null; then
    echo "no homed" >/skipped
    exit 77
fi

inspect() {
    # As updating disk-size-related attributes can take some time on some
    # filesystems, let's drop these fields before comparing the outputs to
    # avoid unexpected fails. To see the full outputs of both homectl &
    # userdbctl (for debugging purposes) drop the fields just before the
    # comparison.
    local USERNAME="${1:?}"
    homectl inspect "$USERNAME" | tee /tmp/a
    userdbctl user "$USERNAME" | tee /tmp/b

    # diff uses the grep BREs for pattern matching
    diff -I '^\s*Disk \(Size\|Free\|Floor\|Ceiling\|Usage\):' /tmp/{a,b}
    rm /tmp/{a,b}

    homectl inspect --json=pretty "$USERNAME"
}

wait_for_exist() {
    timeout 2m bash -c "until homectl inspect '${1:?}'; do sleep 2; done"
}

wait_for_state() {
    timeout 2m bash -c "until homectl inspect '${1:?}' | grep -F 'State: $2' >/dev/null; do sleep 2; done"
}

cleanup_update_auto_resize_mode_without_space() (
    set +e

    rm -f /tmp/no-space-update.create /home/no-space-update.filler /home/no-space-update.home

    if homectl inspect no-space-update >/dev/null 2>&1; then
        homectl deactivate no-space-update 2>/dev/null
        wait_for_state no-space-update inactive 2>/dev/null
        homectl remove no-space-update 2>/dev/null
    fi

    mount /home -o remount,size=290M || :
    systemctl restart systemd-homed.service || :
    return 0
)

FSTYPE="$(stat --file-system --format "%T" /)"

systemctl start systemd-homed.service systemd-userdbd.socket

# Create a tmpfs to use as backing store for the normal test.  The persistent
# wrapped-key lane keeps /home on the root image so its identity record survives
# all three QEMU processes.
mkdir -p /home
if [[ -z "${SYSTEMD_TEST_HW_WRAPPED_PHASE:-}" ]]; then
    mount -t tmpfs tmpfs /home -o size=290M
fi

# Make sure systemd-homed takes notice of the overmounted /home/
systemctl kill -sUSR1 systemd-homed

testcase_basic() {
    local TMP_SKEL

    TMP_SKEL=$(mktemp -d)
    echo hogehoge >"$TMP_SKEL"/hoge

    # we enable --luks-discard= since we run our tests in a tight VM, hence don't
    # needlessly pressure for storage. We also set the cheapest KDF, since we don't
    # want to waste CI CPU cycles on it. We also effectively disable rate-limiting on
    # the user by allowing 1000 logins per second
    NEWPASSWORD=xEhErW0ndafV4s \
        homectl create test-user \
        --disk-size=min \
        --luks-discard=yes \
        --image-path=/home/test-user.home \
        --luks-pbkdf-type=pbkdf2 \
        --luks-pbkdf-time-cost=1ms \
        --rate-limit-interval=1s \
        --rate-limit-burst=1000 \
        --skel="$TMP_SKEL"
    inspect test-user

    PASSWORD=xEhErW0ndafV4s homectl authenticate test-user

    PASSWORD=xEhErW0ndafV4s homectl activate test-user
    inspect test-user

    PASSWORD=xEhErW0ndafV4s homectl update test-user --real-name="Inline test"
    inspect test-user

    # --member-of=
    systemd-sysusers --inline "g test-group1" "g test-group2"
    # Single group
    PASSWORD=xEhErW0ndafV4s homectl update test-user --member-of="test-group1"
    [[ "$(homectl inspect -j test-user | jq -c .memberOf)" == '["test-group1"]' ]]
    # Multiple groups
    PASSWORD=xEhErW0ndafV4s homectl update test-user --member-of="test-group1,test-group2"
    [[ "$(homectl inspect -j test-user | jq -c .memberOf)" == '["test-group1","test-group2"]' ]]
    # Empty argument
    PASSWORD=xEhErW0ndafV4s homectl update test-user --member-of=
    [[ "$(homectl inspect -j test-user | jq -c .memberOf)" == 'null' ]]
    # Argument shenanigans
    #   - only separators
    (! PASSWORD=xEhErW0ndafV4s homectl update test-user --member-of=",,,,,,,,,,,,,,,,,,")
    #   - invalid group
    (! PASSWORD=xEhErW0ndafV4s homectl update test-user --member-of="test-group1,inv@lid.group?")
    #   - separators & valid groups
    PASSWORD=xEhErW0ndafV4s homectl update test-user --member-of=",,,,,test-group1,,,,,,,,,,,,,,test-group2,"
    [[ "$(homectl inspect -j test-user | jq -c .memberOf)" == '["test-group1","test-group2"]' ]]
    #   - duplicate groups
    PASSWORD=xEhErW0ndafV4s homectl update test-user --member-of="test-group2,test-group1,test-group1,test-group2"
    [[ "$(homectl inspect -j test-user | jq -c .memberOf)" == '["test-group1","test-group2"]' ]]

    homectl deactivate test-user
    inspect test-user

    PASSWORD=xEhErW0ndafV4s NEWPASSWORD=yPN4N0fYNKUkOq homectl passwd test-user
    inspect test-user

    PASSWORD=yPN4N0fYNKUkOq homectl activate test-user
    inspect test-user

    SYSTEMD_LOG_LEVEL=debug PASSWORD=yPN4N0fYNKUkOq NEWPASSWORD=xEhErW0ndafV4s homectl passwd test-user
    inspect test-user

    homectl deactivate test-user
    inspect test-user

    homectl update test-user --real-name "Offline test" --offline
    inspect test-user

    PASSWORD=xEhErW0ndafV4s homectl activate test-user
    inspect test-user

    # Ensure that the offline changes were propagated in
    grep "Offline test" /home/test-user/.identity

    homectl deactivate test-user
    inspect test-user

    PASSWORD=xEhErW0ndafV4s homectl update test-user --real-name="Inactive test"
    inspect test-user

    PASSWORD=xEhErW0ndafV4s homectl activate test-user
    inspect test-user

    homectl deactivate test-user
    inspect test-user

    # Do some keyring tests, but only on real kernels, since keyring access inside of containers will fail
    # (See: https://github.com/systemd/systemd/issues/17606)
    if ! systemd-detect-virt -cq ; then
        PASSWORD=xEhErW0ndafV4s homectl activate test-user
        inspect test-user

        # Key should now be in the keyring
        homectl update test-user --real-name "Keyring Test"
        inspect test-user

        # These commands shouldn't use the keyring
        (! timeout 5s homectl authenticate test-user )
        (! NEWPASSWORD="foobar" timeout 5s homectl passwd test-user )

        homectl lock test-user
        inspect test-user

        # Key should be gone from keyring
        (! timeout 5s homectl update test-user --real-name "Keyring Test 2" )

        PASSWORD=xEhErW0ndafV4s homectl unlock test-user
        inspect test-user

        # Key should have been re-instantiated into the keyring
        homectl update test-user --real-name "Keyring Test 3"
        inspect test-user

        homectl deactivate test-user
        inspect test-user
    fi

    # Do some resize tests, but only if we run on real kernels and are on btrfs, as quota inside of containers
    # will fail and minimizing while active only works on btrfs.
    if ! systemd-detect-virt -cq && [[ "$FSTYPE" == "btrfs" ]]; then
        # grow while inactive
        PASSWORD=xEhErW0ndafV4s homectl resize test-user 300M
        inspect test-user

        # minimize while inactive
        PASSWORD=xEhErW0ndafV4s homectl resize test-user min
        inspect test-user

        PASSWORD=xEhErW0ndafV4s homectl activate test-user
        inspect test-user

        # grow while active
        PASSWORD=xEhErW0ndafV4s homectl resize test-user max
        inspect test-user

        # minimize while active
        PASSWORD=xEhErW0ndafV4s homectl resize test-user 0
        inspect test-user

        # grow while active
        PASSWORD=xEhErW0ndafV4s homectl resize test-user 300M
        inspect test-user

        # shrink to original size while active
        PASSWORD=xEhErW0ndafV4s homectl resize test-user 256M
        inspect test-user

        # minimize again
        PASSWORD=xEhErW0ndafV4s homectl resize test-user min
        inspect test-user

        # Increase space, so that we can reasonably rebalance free space between to home dirs
        mount /home -o remount,size=800M

        # create second user
        NEWPASSWORD=uuXoo8ei \
            homectl create test-user2 \
            --disk-size=min \
            --luks-discard=yes \
            --image-path=/home/test-user2.home \
            --luks-pbkdf-type=pbkdf2 \
            --luks-pbkdf-time-cost=1ms \
            --rate-limit-interval=1s \
            --rate-limit-burst=1000
        inspect test-user2

        # activate second user
        PASSWORD=uuXoo8ei homectl activate test-user2
        inspect test-user2

        # set second user's rebalance weight to 100
        PASSWORD=uuXoo8ei homectl update test-user2 --rebalance-weight=100
        inspect test-user2

        # set first user's rebalance weight to quarter of that of the second
        PASSWORD=xEhErW0ndafV4s homectl update test-user --rebalance-weight=25
        inspect test-user

        # synchronously rebalance
        homectl rebalance
        inspect test-user
        inspect test-user2

        wait_for_state test-user2 active
        homectl deactivate test-user2
        wait_for_state test-user2 inactive
        homectl remove test-user2
    fi

    PASSWORD=xEhErW0ndafV4s homectl with test-user -- test ! -f /home/test-user/xyz
    (! PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz)
    PASSWORD=xEhErW0ndafV4s homectl with test-user -- touch /home/test-user/xyz
    PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz
    PASSWORD=xEhErW0ndafV4s homectl with test-user -- rm /home/test-user/xyz
    PASSWORD=xEhErW0ndafV4s homectl with test-user -- test ! -f /home/test-user/xyz
    (! PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz)
    if check_nss_module systemd; then
        [[ "$(PASSWORD=xEhErW0ndafV4s homectl with test-user -- stat -c %U /home/test-user/hoge)" == "test-user" ]]
        [[ "$(PASSWORD=xEhErW0ndafV4s homectl with test-user -- stat -c %u /home/test-user/hoge)" == "$(id -u test-user)" ]]
    fi
    # The machine ID may start with a numeric, and in that case the field name must be quoted.
    [[ "$(PASSWORD=xEhErW0ndafV4s homectl with test-user -- stat -c %u /home/test-user/hoge)" == \
       "$(homectl inspect --json=short test-user | jq .binding.\""$(cat /etc/machine-id)"\".uid)" ]]
    [[ "$(PASSWORD=xEhErW0ndafV4s homectl with test-user -- cat /home/test-user/hoge)" == "$(cat "$TMP_SKEL"/hoge)" ]]

    # Regression tests
    wait_for_state test-user inactive
    /usr/lib/systemd/tests/unit-tests/manual/test-homed-regression-31896 test-user

    wait_for_state test-user inactive
    homectl remove test-user
}

testcase_recovery_key_file() (
    local KEY_DIR
    KEY_DIR="$(mktemp -d /tmp/homed-recovery-key-file.XXXXXX)"
    local KEY_FILE="$KEY_DIR/recovery-key"
    local KEY_FILE2="$KEY_DIR/recovery-key-update"
    local DRY_RUN_OUTPUT="$KEY_DIR/dry-run.out"
    local DRY_RUN_ERROR="$KEY_DIR/dry-run.err"
    local UPDATE_EXISTING_OUTPUT="$KEY_DIR/update-existing.out"
    local KEY_FILE_CONTENT

    homectl remove recoverykeyfiletest 2>/dev/null || true

    trap 'homectl remove recoverykeyfiletest 2>/dev/null || true; rm -rf "$KEY_DIR"' EXIT ERR

    (! NEWPASSWORD=Secr3tRecovery \
        homectl create recoverykeyfiletest \
        --storage=directory \
        --recovery-key-file="$KEY_FILE" \
        --enforce-password-policy=no )

    SYSTEMD_HOME_DRY_RUN=1 \
    NEWPASSWORD=Secr3tRecovery \
        homectl create recoverykeyfiletest \
        --storage=directory \
        --recovery-key=yes \
        --recovery-key-file="$KEY_FILE" \
        --enforce-password-policy=no \
        >"$DRY_RUN_OUTPUT" \
        2>"$DRY_RUN_ERROR"
    grep -E '^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$' "$DRY_RUN_OUTPUT" >/dev/null
    test ! -e "$KEY_FILE"

    NEWPASSWORD=Secr3tRecovery \
        homectl create recoverykeyfiletest \
        --storage=directory \
        --recovery-key=yes \
        --recovery-key-file="$KEY_FILE" \
        --rate-limit-interval=1s \
        --rate-limit-burst=1000 \
        --enforce-password-policy=no

    test -s "$KEY_FILE"
    [[ "$(stat -c "%a" "$KEY_FILE")" == "600" ]]
    grep -E '^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$' "$KEY_FILE" >/dev/null
    PASSWORD="$(cat "$KEY_FILE")" homectl authenticate recoverykeyfiletest

    KEY_FILE_CONTENT="$(cat "$KEY_FILE")"
    PASSWORD=Secr3tRecovery \
        homectl update recoverykeyfiletest \
        --recovery-key=yes \
        --recovery-key-file="$KEY_FILE" \
        >"$UPDATE_EXISTING_OUTPUT"
    [[ "$(cat "$KEY_FILE")" == "$KEY_FILE_CONTENT" ]]
    grep -E '^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$' "$UPDATE_EXISTING_OUTPUT" >/dev/null
    PASSWORD="$(cat "$UPDATE_EXISTING_OUTPUT")" homectl authenticate recoverykeyfiletest

    PASSWORD=Secr3tRecovery \
        homectl update recoverykeyfiletest \
        --recovery-key=yes \
        --recovery-key-file="$KEY_FILE2"

    test -s "$KEY_FILE2"
    [[ "$(stat -c "%a" "$KEY_FILE2")" == "600" ]]
    grep -E '^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$' "$KEY_FILE2" >/dev/null
    PASSWORD="$(cat "$KEY_FILE2")" homectl authenticate recoverykeyfiletest

    homectl remove recoverykeyfiletest
    rm -rf "$KEY_DIR"
)

testcase_update_auto_resize_mode_without_space() {
    local blocks bsize create_output fill_mbytes fill_size filler home_size image
    local fs_stat image_stat image_blocks image_size image_unallocated

    create_output="/tmp/no-space-update.create"
    filler="/home/no-space-update.filler"
    home_size=512M
    image="/home/no-space-update.home"

    trap cleanup_update_auto_resize_mode_without_space RETURN ERR EXIT

    mount /home -o remount,size="$home_size"

    if ! NEWPASSWORD=xEhErW0ndafV4s \
        homectl create no-space-update \
        --storage=luks \
        --disk-size=300M \
        --auto-resize-mode=shrink-and-grow \
        --luks-discard=no \
        --luks-offline-discard=yes \
        --image-path="$image" \
        --luks-pbkdf-type=pbkdf2 \
        --luks-pbkdf-time-cost=1ms \
        --rate-limit-interval=1s \
        --rate-limit-burst=1000 \
        >"$create_output" 2>&1; then

        if grep -F "System does not support selected storage backend" "$create_output" >/dev/null; then
            cat "$create_output"
            echo "LUKS storage backend not supported, skipping update without space test."
            return 0
        fi

        cat "$create_output" >&2
        return 1
    fi
    cat "$create_output"

    PASSWORD=xEhErW0ndafV4s homectl update no-space-update --disk-size=max
    wait_for_state no-space-update inactive

    # Activation still fully allocates luksDiscard=no images while space is available.
    PASSWORD=xEhErW0ndafV4s homectl activate no-space-update
    wait_for_state no-space-update active
    homectl deactivate no-space-update
    wait_for_state no-space-update inactive

    PASSWORD=xEhErW0ndafV4s homectl resize no-space-update 256M
    wait_for_state no-space-update inactive

    PASSWORD=xEhErW0ndafV4s homectl update no-space-update --disk-size=max
    wait_for_state no-space-update inactive

    image_stat="$(stat -c '%s %b' "$image")"
    read -r image_size image_blocks <<<"$image_stat"
    [[ "$image_size" =~ ^[0-9]+$ && "$image_blocks" =~ ^[0-9]+$ ]]
    image_unallocated=$((image_size - image_blocks * 512))
    fs_stat="$(stat --file-system --format "%a %S" /home)"
    read -r blocks bsize <<<"$fs_stat"
    [[ "$blocks" =~ ^[0-9]+$ && "$bsize" =~ ^[0-9]+$ ]]
    fill_size=$((blocks * bsize - 128 * 1024 * 1024))
    fill_mbytes=$((fill_size / 1024 / 1024))
    if [[ "$fill_mbytes" -le 0 ]]; then
        echo "Not enough free space to set up update without space test, skipping."
        return 0
    fi

    # Leave enough room for the small identity update below, but not enough for the old full-image fallocate().
    dd if=/dev/zero of="$filler" bs=1M count="$fill_mbytes"

    fs_stat="$(stat --file-system --format "%a %S" /home)"
    read -r blocks bsize <<<"$fs_stat"
    [[ "$blocks" =~ ^[0-9]+$ && "$bsize" =~ ^[0-9]+$ ]]
    if [[ "$image_unallocated" -le $((blocks * bsize)) ]]; then
        printf 'Not enough backing space for the update test: '
        printf 'image_unallocated=%s free_space=%s fill_mbytes=%s\n' \
            "$image_unallocated" "$((blocks * bsize))" "$fill_mbytes"
        return 0
    fi

    systemctl restart systemd-homed.service
    wait_for_exist no-space-update

    PASSWORD=xEhErW0ndafV4s homectl authenticate no-space-update

    PASSWORD=xEhErW0ndafV4s homectl update no-space-update \
        --luks-discard=yes \
        --luks-offline-discard=no

    PASSWORD=xEhErW0ndafV4s homectl update no-space-update \
        --luks-discard=no \
        --luks-offline-discard=yes

    PASSWORD=xEhErW0ndafV4s NEWPASSWORD=yPN4N0fYNKUkOq homectl passwd no-space-update
    PASSWORD=yPN4N0fYNKUkOq homectl update no-space-update --auto-resize-mode=off

    homectl inspect no-space-update | grep -F "Auto Resize: off" >/dev/null
}

testcase_blob() {
    # blob directory tests
    # See docs/USER_RECORD_BLOB_DIRS.md
    checkblob() {
        test -f "/var/cache/systemd/home/blob-user/$1"
        stat -c "%u %#a" "/var/cache/systemd/home/blob-user/$1" | grep "^0 0644"
        test -f "/home/blob-user/.identity-blob/$1"
        stat -c "%u %#a" "/home/blob-user/.identity-blob/$1" | grep "^12345 0644"

        diff "/var/cache/systemd/home/blob-user/$1" "$2"
        diff "/var/cache/systemd/home/blob-user/$1" "/home/blob-user/.identity-blob/$1"
    }

    mkdir /tmp/blob1 /tmp/blob2
    echo data1 blob1 >/tmp/blob1/test1
    echo data1 blob2 >/tmp/blob2/test1
    echo data2 blob1 >/tmp/blob1/test2
    echo data2 blob2 >/tmp/blob2/test2
    echo invalid filename >/tmp/blob1/файл
    echo data3 >/tmp/external-test3
    echo avatardata >/tmp/external-avatar
    ln -s /tmp/external-avatar /tmp/external-avatar-lnk
    dd if=/dev/urandom of=/tmp/external-barely-fits bs=1M count=64
    dd if=/dev/urandom of=/tmp/external-toobig bs=1M count=65

    # create w/ prepopulated blob dir
    NEWPASSWORD=EMJuc3zQaMibJo \
        homectl create blob-user \
        --disk-size=min --luks-discard=yes \
        --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms \
        --rate-limit-interval=1s --rate-limit-burst=1000 \
        --uid=12345 \
        --blob=/tmp/blob1
    inspect blob-user
    PASSWORD=EMJuc3zQaMibJo homectl activate blob-user
    inspect blob-user

    test -d /var/cache/systemd/home/blob-user
    stat -c "%u %#a" /var/cache/systemd/home/blob-user | grep "^0 0755"
    test -d /home/blob-user/.identity-blob
    stat -c "%u %#a" /home/blob-user/.identity-blob | grep "^12345 0700"

    checkblob test1 /tmp/blob1/test1
    (! checkblob test1 /tmp/blob2/test1 )
    checkblob test2 /tmp/blob1/test2
    (! checkblob test2 /tmp/blob2/test2 )
    (! checkblob фаил /tmp/blob1/фаил )
    (! checkblob test3 /tmp/external-test3 )
    (! checkblob avatar /tmp/external-avatar )

    # append files to existing blob, both well-known and other
    PASSWORD=EMJuc3zQaMibJo \
        homectl update blob-user \
        -b test3=/tmp/external-test3 --avatar=/tmp/external-avatar
    inspect blob-user
    checkblob test1 /tmp/blob1/test1
    (! checkblob test1 /tmp/blob2/test1 )
    checkblob test2 /tmp/blob1/test2
    (! checkblob test2 /tmp/blob2/test2 )
    (! checkblob фаил /tmp/blob1/фаил )
    checkblob test3 /tmp/external-test3
    checkblob avatar /tmp/external-avatar

    # delete files from existing blob, both well-known and other
    PASSWORD=EMJuc3zQaMibJo \
        homectl update blob-user \
        -b test3= --avatar=
    inspect blob-user
    checkblob test1 /tmp/blob1/test1
    (! checkblob test1 /tmp/blob2/test1 )
    checkblob test2 /tmp/blob1/test2
    (! checkblob test2 /tmp/blob2/test2 )
    (! checkblob фаил /tmp/blob1/фаил )
    (! checkblob test3 /tmp/external-test3 )
    (! checkblob avatar /tmp/external-avatar )

    # swap entire blob directory
    PASSWORD=EMJuc3zQaMibJo \
        homectl update blob-user \
        -b /tmp/blob2
    inspect blob-user
    (! checkblob test1 /tmp/blob1/test1 )
    checkblob test1 /tmp/blob2/test1
    (! checkblob test2 /tmp/blob1/test2 )
    checkblob test2 /tmp/blob2/test2
    (! checkblob фаил /tmp/blob1/фаил )
    (! checkblob test3 /tmp/external-test3 )
    (! checkblob avatar /tmp/external-avatar )

    # create and delete files while swapping blob directory. Also symlinks.
    PASSWORD=EMJuc3zQaMibJo \
        homectl update blob-user \
        -b /tmp/blob1 -b test2= -b test3=/tmp/external-test3 --avatar=/tmp/external-avatar-lnk
    inspect blob-user
    checkblob test1 /tmp/blob1/test1
    (! checkblob test1 /tmp/blob2/test1 )
    (! checkblob test2 /tmp/blob1/test2 )
    (! checkblob test2 /tmp/blob2/test2 )
    (! checkblob фаил /tmp/blob1/фаил )
    checkblob test3 /tmp/external-test3
    checkblob avatar /tmp/external-avatar # target of the link

    # clear the blob directory
    PASSWORD=EMJuc3zQaMibJo \
        homectl update blob-user \
        -b /tmp/blob2 -b test3=/tmp/external-test3 --blob=
    inspect blob-user
    (! checkblob test1 /tmp/blob1/test1 )
    (! checkblob test1 /tmp/blob2/test1 )
    (! checkblob test2 /tmp/blob1/test2 )
    (! checkblob test2 /tmp/blob2/test2 )
    (! checkblob фаил /tmp/blob1/фаил )
    (! checkblob test3 /tmp/external-test3 )
    (! checkblob avatar /tmp/external-avatar )

    # file that's exactly 64M still fits
    # FIXME: Figure out why this fails on ext4.
    if [[ "$FSTYPE" != "ext2/ext3" ]]; then
        PASSWORD=EMJuc3zQaMibJo \
            homectl update blob-user \
            -b barely-fits=/tmp/external-barely-fits
        (! checkblob test1 /tmp/blob1/test1 )
        (! checkblob test1 /tmp/blob2/test1 )
        (! checkblob test2 /tmp/blob1/test2 )
        (! checkblob test2 /tmp/blob2/test2 )
        (! checkblob фаил /tmp/blob1/фаил )
        (! checkblob test3 /tmp/external-test3 )
        (! checkblob avatar /tmp/external-avatar )
        checkblob barely-fits /tmp/external-barely-fits
    fi

    # error out if the file is too big
    (! PASSWORD=EMJuc3zQaMibJo homectl update blob-user -b huge=/tmp/external-toobig )

    # error out if filenames are invalid
    (! PASSWORD=EMJuc3zQaMibJo homectl update blob-user -b .hidden=/tmp/external-test3 )
    (! PASSWORD=EMJuc3zQaMibJo homectl update blob-user -b "with spaces=/tmp/external-test3" )
    (! PASSWORD=EMJuc3zQaMibJo homectl update blob-user -b with=equals=/tmp/external-test3 )
    (! PASSWORD=EMJuc3zQaMibJo homectl update blob-user -b файл=/tmp/external-test3 )
    (! PASSWORD=EMJuc3zQaMibJo homectl update blob-user -b special@chars=/tmp/external-test3 )

    # Make sure offline updates to blobs get propagated in
    homectl deactivate blob-user
    inspect blob-user
    homectl update blob-user --offline -b barely-fits= -b propagated=/tmp/external-test3
    inspect blob-user
    PASSWORD=EMJuc3zQaMibJo homectl activate blob-user
    inspect blob-user
    (! checkblob barely-fits /tmp/external-barely-fits )
    checkblob propagated /tmp/external-test3

    homectl deactivate blob-user
    wait_for_state blob-user inactive
    homectl remove blob-user
}

testcase_userdbctl() {
    # userdbctl tests
    export PAGER=

    # Create a couple of user/group records to test io.systemd.DropIn
    # See docs/USER_RECORD.md and docs/GROUP_RECORD.md
    mkdir -p /run/userdb/
    cat >"/run/userdb/dropingroup.group" <<\EOF
{
    "groupName" : "dropingroup",
    "gid"       : 1000000
}
EOF
    cat >"/run/userdb/dropinuser.user" <<\EOF
{
    "userName" : "dropinuser",
    "uid"      : 2000000,
    "realName" : "🐱",
    "memberOf" : [
        "dropingroup"
    ]
}
EOF
    cat >"/run/userdb/dropinuser.user-privileged" <<\EOF
{
    "privileged" : {
        "hashedPassword" : [
            "$6$WHBKvAFFT9jKPA4k$OPY4D4TczKN/jOnJzy54DDuOOagCcvxxybrwMbe1SVdm.Bbr.zOmBdATp.QrwZmvqyr8/SafbbQu.QZ2rRvDs/"
        ],
        "sshAuthorizedKeys" : [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA//dxI2xLg4MgxIKKZv1nqwTEIlE/fdakii2Fb75pG+ foo@bar.tld",
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMlaqG2rTMje5CQnfjXJKmoSpEVJ2gWtx4jBvsQbmee2XbU/Qdq5+SRisssR9zVuxgg5NA5fv08MgjwJQMm+csc= hello@world.tld"
        ]
    }
}
EOF
    # Set permissions and create necessary symlinks as described in nss-systemd(8)
    chmod 0600 "/run/userdb/dropinuser.user-privileged"
    ln -svrf "/run/userdb/dropingroup.group" "/run/userdb/1000000.group"
    ln -svrf "/run/userdb/dropinuser.user" "/run/userdb/2000000.user"
    ln -svrf "/run/userdb/dropinuser.user-privileged" "/run/userdb/2000000.user-privileged"

    userdbctl
    userdbctl --version
    userdbctl --help --no-pager
    userdbctl --no-legend
    userdbctl --output=classic
    userdbctl --output=friendly
    userdbctl --output=table
    userdbctl --output=json | jq
    userdbctl -j --json=pretty | jq
    userdbctl -j --json=short | jq
    userdbctl --with-varlink=no

    userdbctl user
    userdbctl user -S
    userdbctl user -IS
    userdbctl user -R
    userdbctl user --disposition=regular --disposition=intrinsic
    userdbctl user kkkk -z
    userdbctl user --uid-min=100 --uid-max=100
    userdbctl user -B
    userdbctl user testuser
    userdbctl user root
    userdbctl user testuser root
    userdbctl user -j testuser root | jq
    # Check only UID for the nobody user, since the name is build-configurable
    userdbctl user --with-nss=no --synthesize=yes
    userdbctl user --with-nss=no --synthesize=yes 0 root 65534
    userdbctl user dropinuser
    userdbctl user 2000000
    userdbctl user --with-nss=no --with-varlink=no --synthesize=no --multiplexer=no dropinuser
    userdbctl user --with-nss=no 2000000
    (! userdbctl user '')
    (! userdbctl user 🐱)
    (! userdbctl user 🐱 '' bar)
    (! userdbctl user i-do-not-exist)
    (! userdbctl user root i-do-not-exist testuser)
    (! userdbctl user --with-nss=no --synthesize=no 0 root 65534)
    (! userdbctl user -N root nobody)
    (! userdbctl user --with-dropin=no dropinuser)
    (! userdbctl user --with-dropin=no 2000000)

    userdbctl group
    userdbctl group -S
    userdbctl group -IS
    userdbctl group -R
    userdbctl group --disposition=regular --disposition=intrinsic
    userdbctl group kkkk -z
    userdbctl group --uid-min=100 --uid-max=100
    userdbctl group -B
    userdbctl group testuser
    userdbctl group root
    userdbctl group testuser root
    userdbctl group -j testuser root | jq
    # Check only GID for the nobody group, since the name is build-configurable
    userdbctl group --with-nss=no --synthesize=yes
    userdbctl group --with-nss=no --synthesize=yes 0 root 65534
    userdbctl group dropingroup
    userdbctl group 1000000
    userdbctl group --with-nss=no --with-varlink=no --synthesize=no --multiplexer=no dropingroup
    userdbctl group --with-nss=no 1000000
    (! userdbctl group '')
    (! userdbctl group 🐱)
    (! userdbctl group 🐱 '' bar)
    (! userdbctl group i-do-not-exist)
    (! userdbctl group root i-do-not-exist testuser)
    (! userdbctl group --with-nss=no --synthesize=no 0 root 65534)
    (! userdbctl group --with-dropin=no dropingroup)
    (! userdbctl group --with-dropin=no 1000000)

    userdbctl users-in-group
    userdbctl users-in-group testuser
    userdbctl users-in-group testuser root
    userdbctl users-in-group -j testuser root | jq
    userdbctl users-in-group 🐱
    (! userdbctl users-in-group '')
    (! userdbctl users-in-group foo '' bar)

    userdbctl groups-of-user
    userdbctl groups-of-user testuser
    userdbctl groups-of-user testuser root
    userdbctl groups-of-user -j testuser root | jq
    userdbctl groups-of-user 🐱
    (! userdbctl groups-of-user '')
    (! userdbctl groups-of-user foo '' bar)

    userdbctl services
    userdbctl services -j | jq

    varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{"userName":"testuser","service":"io.systemd.Multiplexer"}'
    varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{"userName":"root","service":"io.systemd.Multiplexer"}'
    varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{"userName":"dropinuser","service":"io.systemd.Multiplexer"}'
    varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{"uid":2000000,"service":"io.systemd.Multiplexer"}'
    (! varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{"userName":"","service":"io.systemd.Multiplexer"}')
    (! varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{"userName":"🐱","service":"io.systemd.Multiplexer"}')
    (! varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{"userName":"i-do-not-exist","service":"io.systemd.Multiplexer"}')

    userdbctl ssh-authorized-keys dropinuser | tee /tmp/authorized-keys
    grep "ssh-ed25519" /tmp/authorized-keys
    grep "ecdsa-sha2-nistp256" /tmp/authorized-keys
    echo "my-top-secret-key 🐱" >/tmp/my-top-secret-key
    userdbctl ssh-authorized-keys dropinuser --chain /usr/bin/cat /tmp/my-top-secret-key | tee /tmp/authorized-keys
    grep "ssh-ed25519" /tmp/authorized-keys
    grep "ecdsa-sha2-nistp256" /tmp/authorized-keys
    grep "my-top-secret-key 🐱" /tmp/authorized-keys
    (! userdbctl ssh-authorized-keys 🐱)
    (! userdbctl ssh-authorized-keys dropin-user --chain)
    (! userdbctl ssh-authorized-keys dropin-user --chain '')
    (! SYSTEMD_LOG_LEVEL=debug userdbctl ssh-authorized-keys dropin-user --chain /usr/bin/false)

    # Check that invocations with --chain work as expected
    userdbctl ssh-authorized-keys --chain dropin-user /bin/echo --asdf | grep -e --asdf
    userdbctl ssh-authorized-keys dropin-user --chain /bin/echo --asdf | grep -e --asdf
    userdbctl ssh-authorized-keys dropin-user /bin/echo --chain --asdf | grep -e --asdf
    userdbctl ssh-authorized-keys --chain dropin-user -- /bin/echo --asdf | grep -e --asdf
    userdbctl ssh-authorized-keys --chain -- dropin-user /bin/echo --asdf | grep -e --asdf
    userdbctl --chain -- ssh-authorized-keys dropin-user /bin/echo --asdf | grep -e --asdf
    (! userdbctl --chain -- ssh-authorized-keys dropin-user -- /bin/echo --asdf)

    (! userdbctl '')
    for opt in json multiplexer output synthesize with-dropin with-nss with-varlink; do
        (! userdbctl "--$opt=''")
        (! userdbctl "--$opt='🐱'")
        (! userdbctl "--$opt=foo")
        (! userdbctl "--$opt=foo" "--$opt=''" "--$opt=🐱")
    done
}

cleanup_ssh() (
    set +e

    systemctl is-active -q mysshserver.socket && systemctl stop mysshserver.socket
    rm -f /tmp/homed.id_ecdsa /run/systemd/system/mysshserver{@.service,.socket}
    systemctl daemon-reload
    if homectl inspect homedsshtest &>/dev/null; then
        wait_for_state homedsshtest inactive
        homectl remove homedsshtest
    fi
    for dir in /etc /usr/lib; do
        if [[ -f "$dir/pam.d/sshd.bak" ]]; then
            mv "$dir/pam.d/sshd.bak" "$dir/pam.d/sshd"
        fi
    done
)

testcase_ssh() {
    # FIXME: sshd seems to crash inside asan currently, skip the actual ssh test hence
    if [[ -v ASAN_OPTIONS ]]; then
        return 0
    fi

    # 'ssh homedsshtest@localhost' requires systemd NSS module.
    if ! check_nss_module systemd; then
        return 0
    fi

    if ! command -v ssh >/dev/null || ! command -v sshd >/dev/null; then
        echo "ssh/sshd is not installed, skipping the ssh test."
        return 0
    fi

    trap cleanup_ssh RETURN ERR EXIT

    # Test that SSH logins work with delayed unlocking
    ssh-keygen -N '' -C '' -t ecdsa -f /tmp/homed.id_ecdsa
    NEWPASSWORD=hunter4711 \
        homectl create \
        --disk-size=min \
        --luks-discard=yes \
        --luks-pbkdf-type=pbkdf2 \
        --luks-pbkdf-time-cost=1ms \
        --rate-limit-interval=1s \
        --rate-limit-burst=1000 \
        --enforce-password-policy=no \
        --ssh-authorized-keys=@/tmp/homed.id_ecdsa.pub \
        --stop-delay=0 \
        homedsshtest
    homectl inspect homedsshtest

    mkdir -p /etc/ssh
    test -f /etc/ssh/ssh_host_ecdsa_key || ssh-keygen -t ecdsa -C '' -N '' -f /etc/ssh/ssh_host_ecdsa_key

    # ssh wants this dir around, but distros cannot agree on a common name for it, let's just create all that
    # are aware of distros use
    mkdir -p /usr/share/empty.sshd /var/empty /var/empty/sshd /run/sshd

    for dir in /etc /usr/lib; do
        if [[ -f "$dir/pam.d/sshd" ]]; then
            mv "$dir/pam.d/sshd" "$dir/pam.d/sshd.bak"
            cat >"$dir/pam.d/sshd" <<EOF
auth [success=done authtok_err=bad perm_denied=bad maxtries=bad default=ignore] pam_systemd_home.so
auth    sufficient pam_unix.so nullok
auth    required   pam_deny.so
account [success=done authtok_expired=bad new_authtok_reqd=bad maxtries=bad acct_expired=bad default=ignore] pam_systemd_home.so
account required   pam_unix.so
session optional   pam_systemd_home.so debug
session optional   pam_systemd.so
session required   pam_unix.so
EOF
            break
        fi
    done

    mkdir -p /etc/sshd/
    cat >/etc/ssh/sshd_config <<EOF
AuthorizedKeysCommand /usr/bin/userdbctl ssh-authorized-keys %u
AuthorizedKeysCommandUser root
UsePAM yes
AcceptEnv PASSWORD
LogLevel DEBUG3
EOF

    cat >/run/systemd/system/mysshserver.socket <<EOF
[Socket]
ListenStream=4711
Accept=yes
EOF

    cat >/run/systemd/system/mysshserver@.service <<EOF
[Service]
ExecStart=-sshd -i -d -e
StandardInput=socket
StandardOutput=socket
StandardError=journal
EOF

    systemctl daemon-reload
    systemctl start mysshserver.socket

    userdbctl user -j homedsshtest

    ssh -t -t -4 -p 4711 -i /tmp/homed.id_ecdsa \
        -o "SetEnv PASSWORD=hunter4711" -o "StrictHostKeyChecking no" \
        homedsshtest@localhost echo zzz | tr -d '\r' | tee /tmp/homedsshtest.out
    grep -E "^zzz$" /tmp/homedsshtest.out
    rm /tmp/homedsshtest.out

    ssh -t -t -4 -p 4711 -i /tmp/homed.id_ecdsa \
        -o "SetEnv PASSWORD=hunter4711" -o "StrictHostKeyChecking no" \
        homedsshtest@localhost env
}

testcase_alias() {
    NEWPASSWORD=hunter4711 homectl create aliastest --storage=directory --alias=aliastest2 --alias=aliastest3 --realm=myrealm

    homectl inspect aliastest
    homectl inspect aliastest2
    homectl inspect aliastest3
    homectl inspect aliastest@myrealm
    homectl inspect aliastest2@myrealm
    homectl inspect aliastest3@myrealm

    userdbctl user aliastest
    userdbctl user aliastest2
    userdbctl user aliastest3
    userdbctl user aliastest@myrealm
    userdbctl user aliastest2@myrealm
    userdbctl user aliastest3@myrealm

    if check_nss_module systemd; then
        getent passwd aliastest
        getent passwd aliastest2
        getent passwd aliastest3
        getent passwd aliastest@myrealm
        getent passwd aliastest2@myrealm
        getent passwd aliastest3@myrealm
    fi

    homectl remove aliastest
}

testcase_quota() {
    # 'run0 -u' requires systemd NSS module.
    if ! check_nss_module systemd; then
        return 0
    fi

    NEWPASSWORD=quux homectl create tmpfsquota --storage=subvolume --dev-shm-limit=50K --tmp-limit=50K -P
    for p in /dev/shm /tmp; do
        if findmnt -n -o options "$p" | grep usrquota >/dev/null; then
            # Check if we can display the quotas. If we cannot, than it's likely
            # that PID1 was also not able to set the limits and we should not fail
            # in the tests below.
            /usr/lib/systemd/tests/unit-tests/manual/test-display-quota tmpfsquota "$p" || set +e

            run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u tmpfsquota dd if=/dev/zero of="$p/quotatestfile1" bs=1024 count=30
            (! run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u tmpfsquota dd if=/dev/zero of="$p/quotatestfile2" bs=1024 count=30)
            run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u tmpfsquota rm "$p/quotatestfile1" "$p/quotatestfile2"
            run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u tmpfsquota dd if=/dev/zero of="$p/quotatestfile1" bs=1024 count=30
            run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u tmpfsquota rm "$p/quotatestfile1"

            set -e
        fi
    done

    systemctl stop user@"$(id -u tmpfsquota)".service
    wait_for_state tmpfsquota inactive
    homectl remove tmpfsquota
}

testcase_subarea() {
    # 'run0 -u' requires systemd NSS module.
    if ! check_nss_module systemd; then
        return 0
    fi

    NEWPASSWORD=quux homectl create subareatest --storage=subvolume -P
    run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest mkdir Areas
    run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest cp -av /etc/skel Areas/furb
    run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest cp -av /etc/skel Areas/molb
    run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest ln -s /home/srub Areas/srub
    run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest ln -s /root Areas/root

    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest bash -c 'echo $HOME')" = "/home/subareatest"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest bash -c 'echo x$XDG_AREA')" = "x"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $HOME')" = "/home/subareatest/Areas/furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $XDG_AREA')" = "furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/furb"

    PASSWORD=quux homectl update subareatest --default-area=molb
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest bash -c 'echo $HOME')" = "/home/subareatest/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest bash -c 'echo $XDG_AREA')" = "molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $HOME')" = "/home/subareatest/Areas/furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $XDG_AREA')" = "furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/furb"

    # Install a PK rule that allows 'subareatest' user to invoke run0 without password, just for testing
    cat >/usr/share/polkit-1/rules.d/subareatest.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.user == "subareatest") {
        return polkit.Result.YES;
    }
});
EOF

    # Test "recursive" operation
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb bash -c 'echo $HOME')" = "/home/subareatest/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb bash -c 'echo $XDG_AREA')" = "molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $HOME')" = "/home/subareatest/Areas/furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $XDG_AREA')" = "furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/furb"

    # Test symlinked area
    mkdir -p /home/srub
    chown subareatest:subareatest /home/srub
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=srub bash -c 'echo $HOME')" = "/home/srub"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=srub bash -c 'echo $XDG_AREA')" = "srub"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=srub bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/srub"

    # Verify that login into an area not owned by target user will be redirected to main area
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=root bash -c 'echo $HOME')" = "/home/subareatest"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=root bash -c 'echo x$XDG_AREA')" = "x"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=root bash -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)"

    systemctl stop user@"$(id -u subareatest)".service

    wait_for_state subareatest inactive
    homectl remove subareatest
}

testcase_sign() {
    # Test signing key logic
    homectl list-signing-keys | grep local.public >/dev/null
    (! (homectl list-signing-keys | grep signtest.public >/dev/null))

    if built_with_musl; then
        # FIXME: musl does not support yescrypt. Use SHA512 and update signature.
        return 0
    fi

    print_identity() {
        cat <<\EOF
{
    "userName" : "signtest",
    "storage" : "directory",
    "disposition" : "regular",
    "privileged" : {
        "hashedPassword" : [
            "$y$j9T$I5Wxfm.fyg.RRWlgWw.rI1$gnQqGtbpPexqxZJkWMq8FxQi5Swc.CWeKtM8LwvEUB6"
        ]
    },
    "enforcePasswordPolicy" : false,
    "lastChangeUSec" : 1740677608017608,
    "lastPasswordChangeUSec" : 1740677608017608,
    "signature" : [
        {
            "data" : "Gl4wtc0sMjVnsH6FQwG/0M+x0nLI5cvvdtSSCttUu1gNtXqYn0UI4wZi/7zX35ERht6XHWDlP4d6V8HiAst4Dg==",
            "key" : "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA6uvVaP1vh7O6nIbiOcvyIHRl4ihYSs0R7ctxtz2Zu7E=\n-----END PUBLIC KEY-----\n"
        }
    ],
    "secret" : {
        "password" : [
            "test"
        ]
    }
}
EOF
    }

    # Try with stripping the foreign signature first, this should just work
    print_identity | homectl create -P --identity=- --seize=yes
    wait_for_state signtest inactive
    homectl remove signtest

    # No try again, and don't strip the signature. It will be refused.
    (! (print_identity | homectl create -P --identity=- --seize=no))

    print_public_key() {
        cat <<EOF
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6uvVaP1vh7O6nIbiOcvyIHRl4ihYSs0R7ctxtz2Zu7E=
-----END PUBLIC KEY-----
EOF
    }

    # Let's now add the signing key
    print_public_key | homectl add-signing-key --key-name=signtest.public
    homectl get-signing-key signtest.public | cmp - <(print_public_key)
    homectl list-signing-keys | grep local.public >/dev/null
    homectl list-signing-keys | grep signtest.public >/dev/null

    # Now create the account with this, it should work now
    print_identity | homectl create -P --identity=- --seize=no

    # Verify we can log in
    PASSWORD="test" homectl with signtest true

    # Remove the key, and check again ,should fail now
    wait_for_state signtest inactive
    homectl remove-signing-key signtest.public
    wait_for_state signtest inactive
    (! PASSWORD="test" homectl with signtest true)

    # Verify key is really gone
    homectl list-signing-keys | grep local.public >/dev/null
    (! (homectl list-signing-keys | grep signtest.public >/dev/null))

    # Test unregister + adopt
    mkdir /home/elsewhere
    mv /home/signtest.homedir /home/elsewhere/
    wait_for_state signtest absent
    homectl unregister signtest
    print_public_key | homectl add-signing-key --key-name=signtest.public
    homectl adopt /home/elsewhere/signtest.homedir
    PASSWORD="test" homectl with signtest true

    # Test register
    wait_for_state signtest inactive
    homectl unregister signtest
    homectl register /home/elsewhere/signtest.homedir/.identity
    wait_for_state signtest absent
    homectl unregister signtest

    # Test automatic fixation for anything in /home/
    mv /home/elsewhere/signtest.homedir /home
    rmdir /home/elsewhere
    wait_for_exist signtest
    PASSWORD="test" homectl with signtest true

    # add signing key via credential
    wait_for_state signtest inactive
    homectl remove-signing-key signtest.public
    (! (homectl list-signing-keys | grep signtest.public >/dev/null))
    systemd-run --wait -p "SetCredential=home.add-signing-key.signtest.public:$(print_public_key)" homectl firstboot
    homectl list-signing-keys | grep signtest.public >/dev/null

    # register user via credential
    mkdir /home/elsewhere2
    mv /home/signtest.homedir /home/elsewhere2/
    wait_for_state signtest absent
    homectl unregister signtest
    systemd-run --wait -p "LoadCredential=home.register.signtest:/home/elsewhere2/signtest.homedir/.identity" homectl firstboot
    homectl inspect signtest
    wait_for_state signtest absent
    homectl unregister signtest
    mv /home/elsewhere2/signtest.homedir /home/
    rmdir /home/elsewhere2

    # Remove it all again
    wait_for_exist signtest
    homectl remove-signing-key signtest.public
    homectl remove signtest
}

testcase_match() {
    # Test positive and negative matching
    NEWPASSWORD=test homectl create --storage=directory --nice=5 -P matchtest
    homectl inspect matchtest
    homectl inspect matchtest | grep "Nice: 5"
    PASSWORD=test homectl update -N --nice=7 -T --nice=3 matchtest
    homectl inspect matchtest
    homectl inspect matchtest | grep "Nice: 3"
    PASSWORD=test homectl update -A --default-area=quux1 matchtest
    homectl inspect matchtest
    homectl inspect matchtest | grep "Area: quux1"
    PASSWORD=test homectl update -N --default-area=quux2 matchtest
    homectl inspect matchtest
    homectl inspect matchtest | grep "Area: quux1"
    PASSWORD=test homectl update -T --default-area=quux3 matchtest
    homectl inspect matchtest
    homectl inspect matchtest | grep "Area: quux3"
    homectl remove matchtest
}

testcase_fscrypt() {
    if ! command -v mkfs.ext4 >/dev/null; then
        echo "e2fsprogs not installed, skipping fscrypt test."
        return 0
    fi

    local IMAGE MNT
    IMAGE="$(mktemp /tmp/fscrypt.XXXXXX.img)"
    MNT="$(mktemp -d /tmp/fscrypt-mnt.XXXXXX)"
    # shellcheck disable=SC2064
    trap "homectl deactivate fscrypttest 2>/dev/null || true; homectl remove fscrypttest 2>/dev/null || true; umount '$MNT' 2>/dev/null || true; rm -rf '$MNT' '$IMAGE'" RETURN ERR

    truncate -s 64M "$IMAGE"
    if ! mkfs.ext4 -q -O encrypt "$IMAGE"; then
        echo "mkfs.ext4 -O encrypt unsupported, skipping fscrypt test."
        return 0
    fi

    if ! mount -o loop "$IMAGE" "$MNT"; then
        echo "Cannot loop-mount fscrypt-capable ext4, skipping fscrypt test."
        return 0
    fi

    if ! NEWPASSWORD=fsfsfs1234 homectl create fscrypttest \
            --storage=fscrypt \
            --image-path="$MNT/fscrypttest" \
            --rate-limit-interval=1s --rate-limit-burst=1000; then
        echo "homed fscrypt backend not usable on this kernel, skipping."
        return 0
    fi

    inspect fscrypttest

    (! PASSWORD=wrongpass timeout 10s homectl authenticate fscrypttest </dev/null)

    PASSWORD=fsfsfs1234 homectl authenticate fscrypttest
    PASSWORD=fsfsfs1234 homectl activate fscrypttest
    inspect fscrypttest

    fscrypt_run0() {
        run0 --property=SetCredential=pam.authtok.systemd-run0:"$1" -u fscrypttest \
            bash -c 'keyctl link @u @s; eval "$1"' -- "$2"
    }

    fscrypt_run0 fsfsfs1234 'echo "hello fscrypt" >/home/fscrypttest/file1'
    [[ "$(fscrypt_run0 fsfsfs1234 'cat /home/fscrypttest/file1')" == "hello fscrypt" ]]
    fscrypt_run0 fsfsfs1234 'mkdir /home/fscrypttest/subdir'
    fscrypt_run0 fsfsfs1234 'dd if=/dev/urandom of=/home/fscrypttest/subdir/blob bs=4096 count=8 status=none'
    fscrypt_run0 fsfsfs1234 'cp /home/fscrypttest/subdir/blob /home/fscrypttest/subdir/blob.copy && cmp /home/fscrypttest/subdir/blob /home/fscrypttest/subdir/blob.copy'
    fscrypt_run0 fsfsfs1234 'echo appended >>/home/fscrypttest/file1 && grep -F appended /home/fscrypttest/file1 >/dev/null'
    fscrypt_run0 fsfsfs1234 'rm /home/fscrypttest/subdir/blob.copy && test ! -e /home/fscrypttest/subdir/blob.copy'

    systemctl stop user@"$(id -u fscrypttest)".service 2>/dev/null || true
    homectl deactivate fscrypttest 2>/dev/null || true
    wait_for_state fscrypttest inactive

    # After deactivation the fscrypt-encrypted directory is locked, so cleartext file names should not be visible
    [[ ! -e "$MNT/fscrypttest/file1" ]]

    # Verify we actually use the v2 format
    local SLOT
    SLOT="$(getfattr --absolute-names --only-values -n trusted.fscrypt_slot0 "$MNT/fscrypttest")"
    [[ "${SLOT:0:4}" == "\$v2:" ]] || {
        echo "fscrypt slot 0 is not in v2 format: ${SLOT:0:32}"
        return 1
    }

    PASSWORD=fsfsfs1234 homectl activate fscrypttest
    [[ "$(fscrypt_run0 fsfsfs1234 'head -n1 /home/fscrypttest/file1')" == "hello fscrypt" ]]
    systemctl stop user@"$(id -u fscrypttest)".service 2>/dev/null || true
    homectl deactivate fscrypttest 2>/dev/null || true
    wait_for_state fscrypttest inactive

    homectl update fscrypttest --real-name="Fscrypt Test" --offline
    inspect fscrypttest | grep "Real Name: Fscrypt Test" >/dev/null

    PASSWORD=fsfsfs1234 NEWPASSWORD=newfsfs5678 homectl passwd fscrypttest
    PASSWORD=newfsfs5678 homectl authenticate fscrypttest
    (! PASSWORD=fsfsfs1234 timeout 10s homectl authenticate fscrypttest </dev/null)

    PASSWORD=newfsfs5678 homectl activate fscrypttest
    [[ "$(fscrypt_run0 newfsfs5678 'head -n1 /home/fscrypttest/file1')" == "hello fscrypt" ]]
    fscrypt_run0 newfsfs5678 'rm -r /home/fscrypttest/subdir /home/fscrypttest/file1'
    systemctl stop user@"$(id -u fscrypttest)".service 2>/dev/null || true
    homectl deactivate fscrypttest 2>/dev/null || true
    wait_for_state fscrypttest inactive

    homectl remove fscrypttest
}

testcase_deactivate_busy() {
    # Verify that "homectl deactivate" is robust against transient EBUSY
    # failures of the umount() inside systemd-homework. This used to make
    # TEST-46-HOMED occasionally fail when something briefly held a reference
    # to the home mount at the moment the deactivation tried to unmount it.
    #
    # Reproduce the situation deterministically by spawning a background
    # process whose cwd is the home directory: that holds the mount busy via
    # the kernel's cwd reference until the process exits, so the initial
    # umount2() call in homework will fail with EBUSY. homectl is expected to
    # transparently retry the bus call until it succeeds (once the holder
    # exits).

    NEWPASSWORD=hunter2 homectl create \
        --storage=directory \
        --enforce-password-policy=no \
        busytest
    PASSWORD=hunter2 homectl activate busytest
    inspect busytest

    # Make sure the home is actually mounted before we try to hold it busy,
    # otherwise the subshell below would silently fail to acquire the cwd
    # reference.
    mountpoint /home/busytest

    # Spawn a process whose cwd is inside the home mount. `cd` is a shell
    # builtin so the subshell process itself acquires the cwd reference, and
    # `exec sleep` then preserves it across the exec.
    ( cd /home/busytest && exec sleep 10 ) &
    local busy_pid=$!

    # Wait until the kernel actually reports the cwd of the background
    # process as the home directory, so we know the busy reference is in
    # place before we attempt to deactivate.
    timeout 5 bash -c "until [[ \"\$(readlink /proc/${busy_pid}/cwd 2>/dev/null)\" == /home/busytest ]]; do sleep 0.1; done"

    # The deactivate must succeed eventually: the first umount2() will fail
    # with EBUSY, but homectl retries the call for up to 30 seconds, by
    # which time the background process will have exited and released the
    # cwd reference.
    homectl deactivate busytest
    wait_for_state busytest inactive

    wait "$busy_pid" || true
    homectl remove busytest
}

testcase_identity_groups() {
    NEWPASSWORD=foobar homectl create idgrouptest --storage=directory --shell=/bin/bash --enforce-password-policy=no --rebalance-weight=off
    PASSWORD=foobar homectl activate idgrouptest

    machinectl shell idgrouptest@ /usr/bin/bash -euxo pipefail -c "jq '.memberOf = ((.memberOf // []) + [\"systemd-journal\"] | unique) | .lastChangeUSec = ((.lastChangeUSec // 0) + 3600000000)' /home/idgrouptest/.identity > /home/idgrouptest/.identity.new && mv -f /home/idgrouptest/.identity.new /home/idgrouptest/.identity"
    jq -e '.memberOf | index("systemd-journal") != null' /home/idgrouptest/.identity
    wait_for_state idgrouptest active

    PASSWORD=foobar homectl authenticate idgrouptest

    local groups
    groups="$(machinectl shell idgrouptest@ /usr/bin/groups)"
    (! grep systemd-journal <<<"$groups" >/dev/null)

    homectl deactivate idgrouptest ||:
    wait_for_state idgrouptest inactive
    homectl remove idgrouptest

    # Install a PK rule that allows 'idgrouptest2' user to update homed even
    # though they are not on an fg console, just for testing
    mkdir -p /etc/polkit-1/rules.d
    cat >/etc/polkit-1/rules.d/updatehome.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.home1.update-home-by-owner" &&
        subject.user == "idgrouptest2") {
        return polkit.Result.YES;
    }
});
EOF
    trap 'rm -f /etc/polkit-1/rules.d/updatehome.rules' RETURN ERR EXIT
    systemctl try-reload-or-restart polkit.service

    NEWPASSWORD=foobar homectl create idgrouptest2 --storage=directory --shell=/bin/bash --enforce-password-policy=no --rebalance-weight=off
    PASSWORD=foobar homectl activate idgrouptest2

    cat >/tmp/idgrouptest-add-group.sh <<'EOF'
#!/bin/bash
set -exuo pipefail

loginctl show-session "${XDG_SESSION_ID:?}" -p Active --value | grep '^yes$' >/dev/null
RECORD="$(busctl -j call org.freedesktop.home1 /org/freedesktop/home1 org.freedesktop.home1.Manager GetUserRecordByName s "$USER" | jq -r '.data[0]')"
TS="$(printf '%s' "$RECORD" | jq '.lastChangeUSec')"
NEW_TS=$((TS + 172800000000))
jq --arg g systemd-journal --argjson ts "$NEW_TS" \
   '.memberOf = ((.memberOf // []) + [$g]) | .lastChangeUSec = $ts' \
   ~/.identity > ~/.identity.new
mv -f ~/.identity.new ~/.identity
# Ensure the identity update is persisted before UpdateHomeEx reads it.
sync

UPDATE_TS=$((TS + 1))
UPDATE_RECORD="$(printf '%s' "$RECORD" | jq -c --argjson ts "$UPDATE_TS" --arg p foobar 'del(.binding, .status, .signature) | .lastChangeUSec = $ts | .secret = {password: [$p]}')"
(! busctl call org.freedesktop.home1 /org/freedesktop/home1 org.freedesktop.home1.Manager UpdateHomeEx "sa{sh}t" "$UPDATE_RECORD" 0 0 )
EOF
    chmod +x /tmp/idgrouptest-add-group.sh
    machinectl shell idgrouptest2@ /tmp/idgrouptest-add-group.sh
    rm -f /tmp/idgrouptest-add-group.sh

    PASSWORD=foobar homectl authenticate idgrouptest2

    local groups
    groups="$(machinectl shell idgrouptest2@ /usr/bin/groups)"
    (! grep systemd-journal <<<"$groups" >/dev/null)

    homectl deactivate idgrouptest2 ||:
    wait_for_state idgrouptest2 inactive
    homectl remove idgrouptest2
}

testcase_thin_volume() {
    local metadata_backing="/var/tmp/homed-thin-metadata-$$.img"
    local data_backing="/var/tmp/homed-thin-data-$$.img"
    local config=/run/systemd/homed.conf.d/90-test-thin.conf
    local metadata_loop="" data_loop=""
    local pool_name="homed-test-pool-$$"
    local pool="/dev/mapper/$pool_name"
    local pool_uuid="HOMED-POOL-test-$$"
    local default_user=thin-default-user password=thin-test-password user=thin-user second=thin-user-2
    local data_sectors=$((768 * 1024 * 1024 / 512))

    for command in awk cryptsetup dd dmsetup findmnt fstrim jq losetup modprobe truncate; do
        if ! command -v "$command" >/dev/null; then
            echo "Skipping thin-volume test: $command is not installed"
            return 0
        fi
    done
    modprobe dm-thin-pool ||:
    if ! dmsetup targets | awk '$1 == "thin-pool" { found = 1 } END { exit !found }'; then
        echo "Skipping thin-volume test: dm-thin-pool is unavailable"
        return 0
    fi

    thin_cleanup() {
        set +e
        homectl deactivate "$second"
        homectl remove "$second"
        homectl deactivate "$default_user"
        homectl remove "$default_user"
        homectl deactivate "$user"
        homectl remove "$user"
        homectl remove thin-policy-test
        rm -f "$config"
        systemctl restart systemd-homed.service
        dmsetup remove --retry "$pool_name"
        if [[ -n "$metadata_loop" ]]; then
            losetup --detach "$metadata_loop"
        fi
        if [[ -n "$data_loop" ]]; then
            losetup --detach "$data_loop"
        fi
        rm -f /var/lib/systemd/home/.thin-pool-state /var/lib/systemd/home/.thin-pool-state.lock \
            /run/homed-thin-state-backup-$$
        rm -f "$metadata_backing" "$data_backing"
    }
    trap thin_cleanup EXIT

    truncate --size=16M "$metadata_backing"
    truncate --size=768M "$data_backing"
    metadata_loop="$(losetup --find --show "$metadata_backing")"
    data_loop="$(losetup --find --show "$data_backing")"
    dd if=/dev/zero of="$metadata_loop" bs=4096 count=1 conv=fsync
    rm -f /var/lib/systemd/home/.thin-pool-state /var/lib/systemd/home/.thin-pool-state.lock
    dmsetup create "$pool_name" --uuid "LVM-test-pool-$$" --table \
        "0 $data_sectors thin-pool $metadata_loop $data_loop 512 128 1 error_if_no_space"

    mkdir -p "$(dirname "$config")"
    cat >"$config" <<EOF
[Home]
DefaultStorage=luks
ThinPool=$pool
HardwareWrappedKeys=no
EOF
    systemctl restart systemd-homed.service

    # Raw ownership is mandatory; accepting an LVM UUID would make the numeric ID namespace ambiguous.
    (! NEWPASSWORD="$password" homectl create thin-policy-test \
        --storage=luks --fs-type=ext4 --disk-size=300M \
        --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms)
    (! homectl inspect thin-policy-test)
    dmsetup remove --retry "$pool_name"
    dmsetup create "$pool_name" --uuid "$pool_uuid" --table \
        "0 $data_sectors thin-pool $metadata_loop $data_loop 512 128 1 error_if_no_space"
    systemctl restart systemd-homed.service

    # queue_if_no_space is rejected before any device ID is allocated.
    dmsetup suspend "$pool_name"
    dmsetup reload "$pool_name" --table \
        "0 $data_sectors thin-pool $metadata_loop $data_loop 512 128 0"
    dmsetup resume "$pool_name"
    (! NEWPASSWORD="$password" homectl create thin-policy-test \
        --storage=luks --fs-type=ext4 --disk-size=300M \
        --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms)
    (! homectl inspect thin-policy-test)
    dmsetup suspend "$pool_name"
    dmsetup reload "$pool_name" --table \
        "0 $data_sectors thin-pool $metadata_loop $data_loop 512 128 1 error_if_no_space"
    dmsetup resume "$pool_name"

    local machine_id default_record default_size default_mapping default_device_id
    machine_id="$(cat /etc/machine-id)"
    default_size=$((data_sectors * 512 / 1048576 * 1048576))
    NEWPASSWORD="$password" homectl create "$default_user" \
        --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms
    default_record="$(homectl inspect --json=short "$default_user")"
    default_device_id="$(jq -er --arg m "$machine_id" '.binding[$m].thinDeviceId' <<<"$default_record")"
    [[ "$(jq -er --arg m "$machine_id" \
        '.perMachine[] | select(.matchMachineId | if type == "array" then index($m) else . == $m end) | .diskSize' \
        <<<"$default_record")" == "$default_size" ]]
    default_mapping="homed-$(jq -er '.uuid | gsub("-"; "")' <<<"$default_record")"
    PASSWORD="$password" homectl activate "$default_user"
    [[ "$(dmsetup table "$default_mapping" | awk 'NR == 1 { print $3 }')" == thin ]]
    homectl deactivate "$default_user"
    homectl remove "$default_user"

    NEWPASSWORD="$password" homectl create "$user" \
        --storage=luks --fs-type=ext4 --disk-size=800M \
        --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms

    local record record_uuid device_id image_path mapping usage_before usage_after
    record="$(homectl inspect --json=short "$user")"
    record_uuid="$(jq -er '.uuid' <<<"$record")"
    mapping="homed-${record_uuid//-/}"
    device_id="$(jq -er --arg m "$machine_id" '.binding[$m].thinDeviceId' <<<"$record")"
    (( device_id > default_device_id ))
    image_path="$(jq -er --arg m "$machine_id" '.binding[$m].imagePath' <<<"$record")"
    [[ "$(jq -er --arg m "$machine_id" '.binding[$m].thinPoolUuid' <<<"$record")" == "$pool_uuid" ]]
    [[ "$(jq -er --arg m "$machine_id" '.binding[$m].storage' <<<"$record")" == luks ]]

    PASSWORD="$password" homectl activate "$user"
    [[ "$(dmsetup table "$mapping" | awk 'NR == 1 { print $3 }')" == thin ]]
    dmsetup table "$mapping" | grep -w "$device_id"
    dd if=/dev/zero of="/home/$user/discard-me" bs=1M count=64 conv=fsync
    echo persistent >"/home/$user/persistent"
    sync
    usage_before="$(dmsetup status "$pool_name" | awk '{ print $6 }')"
    rm "/home/$user/discard-me"
    usage_after="$usage_before"
    for _ in {1..10}; do
        fstrim "/home/$user"
        sync
        usage_after="$(dmsetup status "$pool_name" | awk '{ print $6 }')"
        if awk -F '[/ ]' -v before="$usage_before" -v after="$usage_after" \
            'BEGIN { split(before, b, "/"); split(after, a, "/"); exit !(a[1] < b[1]) }'; then
            break
        fi
        sleep 0.2
    done
    awk -v before="$usage_before" -v after="$usage_after" \
        'BEGIN { split(before, b, "/"); split(after, a, "/"); exit !(a[1] < b[1]) }'

    homectl deactivate "$user"

    # Losing the durable allocator must not silently restart allocation at device ID zero.
    cp /var/lib/systemd/home/.thin-pool-state /run/homed-thin-state-backup-$$
    rm /var/lib/systemd/home/.thin-pool-state
    systemctl restart systemd-homed.service
    (! PASSWORD="$password" homectl activate "$user")
    cp /run/homed-thin-state-backup-$$ /var/lib/systemd/home/.thin-pool-state
    rm /run/homed-thin-state-backup-$$

    # The record and allocator are tied to the pool generation UUID, not merely its backing devices.
    dmsetup remove --retry "$pool_name"
    dmsetup create "$pool_name" --uuid "HOMED-POOL-wrong-$$" --table \
        "0 $data_sectors thin-pool $metadata_loop $data_loop 512 128 1 error_if_no_space"
    systemctl restart systemd-homed.service
    (! PASSWORD="$password" homectl activate "$user")
    dmsetup remove --retry "$pool_name"
    dmsetup create "$pool_name" --uuid "$pool_uuid" --table \
        "0 $data_sectors thin-pool $metadata_loop $data_loop 512 128 1 error_if_no_space"
    systemctl restart systemd-homed.service
    PASSWORD="$password" homectl activate "$user"
    grep -Fx persistent "/home/$user/persistent"

    NEWPASSWORD="$password" homectl create "$second" \
        --storage=luks --fs-type=ext4 --disk-size=300M \
        --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms
    PASSWORD="$password" homectl activate "$second"
    dd if=/dev/zero of="/home/$user/concurrent" bs=1M count=32 conv=fsync
    dd if=/dev/zero of="/home/$second/concurrent" bs=1M count=32 conv=fsync

    homectl deactivate "$second"
    homectl remove "$second"
    homectl deactivate "$user"
    homectl remove "$user"
    (! dmsetup info "$mapping")

    trap - EXIT
    thin_cleanup
}

testcase_hw_wrapped_multiboot() {
    if [[ -z "${SYSTEMD_TEST_HW_WRAPPED_PHASE:-}" ]]; then
        echo "Skipping hardware-wrapped multiboot lane without SYSTEMD_TEST_HW_WRAPPED_PHASE"
        return 0
    fi

    local phase="${SYSTEMD_TEST_HW_WRAPPED_PHASE:?set SYSTEMD_TEST_HW_WRAPPED_PHASE to 1, 2, or 3}"
    local device="${SYSTEMD_TEST_HW_WRAPPED_DEVICE:?set SYSTEMD_TEST_HW_WRAPPED_DEVICE to the dedicated UFS block device}"
    local config=/run/systemd/homed.conf.d/90-test-hw-wrapped.conf
    local state_dir=/var/lib/systemd/tests/homed-hw-wrapped
    local state_file="$state_dir/state"
    local pool_name=homed-hw-pool pool=/dev/mapper/homed-hw-pool user=wrapped-persistent-user luks_uuid
    local metadata_device data_device pool_uuid data_sectors
    local image_path=
    local password=wrapped-initial-password rotated=wrapped-rotated-password

    for command in awk blockdev cryptsetup dd dmsetup findmnt fstrim jq lsblk sfdisk sha256sum udevadm; do
        command -v "$command" >/dev/null
    done
    device="$(realpath -e "$device")"
    [[ -b "$device" ]]
    [[ "$phase" =~ ^[123]$ ]]

    mkdir -p "$(dirname "$config")" "$state_dir"
    cat >"$config" <<EOF
[Home]
ThinPool=$pool
HardwareWrappedKeys=yes
EOF

    hw_open_image() {
        local partition partition_node start sector_size count

        if [[ ! -b "/dev/mapper/$thin_mapping" ]]; then
            dmsetup create "$thin_mapping" --uuid "HOMED-THIN-${home_uuid//-/}" --table \
                "0 $((2 * 1024 * 1024 * 1024 / 512)) thin $pool $thin_device_id"
        fi
        partition="$(sfdisk --json "/dev/mapper/$thin_mapping")"
        start="$(jq -er '.partitiontable.partitions[0].start' <<<"$partition")"
        partition_node="$(jq -er '.partitiontable.partitions[0].node' <<<"$partition")"
        sector_size="$(jq -er '.partitiontable.sectorsize' <<<"$partition")"
        (( sector_size > 0 && 32 * 1024 * 1024 % sector_size == 0 ))
        count=$((32 * 1024 * 1024 / sector_size))
        image_path=/run/homed-hw-wrapped-header.raw
        dd if="/dev/mapper/$thin_mapping" of="$image_path" bs="$sector_size" skip="$start" count="$count" iflag=fullblock status=none
        udevadm settle
        if [[ -b "$partition_node" ]]; then
            dmsetup remove --retry "$partition_node"
        fi
        dmsetup remove --retry "$thin_mapping"
        [[ -f "$image_path" ]]
        [[ "$(cryptsetup luksUUID "$image_path")" == "$luks_uuid" ]]
    }

    hw_close_image() {
        rm -f "$image_path"
        image_path=
    }

    if [[ "$phase" == 1 ]]; then
        printf 'label: gpt\n,32M,L\n,,L\n' | sfdisk --wipe=always "$device"
        udevadm settle
        mapfile -t pool_partitions < <(lsblk --json --paths --output PATH,TYPE "$device" |
            jq -er '.blockdevices[0].children[] | select(.type == "part") | .path')
        [[ "${#pool_partitions[@]}" == 2 ]]
        metadata_device="${pool_partitions[0]}"
        data_device="${pool_partitions[1]}"
        dd if=/dev/zero of="$metadata_device" bs=4096 count=1 conv=fsync
    else
        [[ -s "$state_file" ]]
        # shellcheck source=/dev/null
        source "$state_file"
    fi

    if [[ -z "${metadata_device:-}" || -z "${data_device:-}" ]]; then
        mapfile -t pool_partitions < <(lsblk --json --paths --output PATH,TYPE "$device" |
            jq -er '.blockdevices[0].children[] | select(.type == "part") | .path')
        metadata_device="${pool_partitions[0]}"
        data_device="${pool_partitions[1]}"
    fi
    pool_uuid="HOMED-POOL-$(lsblk --noheadings --raw --output PARTUUID "$metadata_device")-$(lsblk --noheadings --raw --output PARTUUID "$data_device")"
    data_sectors="$(blockdev --getsz "$data_device")"
    dmsetup create "$pool_name" --uuid "$pool_uuid" --table \
        "0 $data_sectors thin-pool $metadata_device $data_device 512 128 1 error_if_no_space"

    systemctl restart systemd-homed.service

    hw_dm_child() {
        dmsetup deps --options devname --noheadings "$1" |
            sed -n 's/.*(\([^()]\+\)).*/\1/p'
    }

    hw_assert_metadata() {
        local image_path="$1" metadata

        metadata="$(cryptsetup luksDump --dump-json-metadata "$image_path")"
        [[ "$(jq -r '.segments."0".key_type' <<<"$metadata")" == hw-wrapped ]]
        jq -e '.config.requirements.mandatory | index("hw-wrapped-key")' <<<"$metadata"
        jq -e '.config.requirements.mandatory | index("hw-wrapped-key-integrity")' <<<"$metadata"
    }

    hw_assert_topology() {
        local source top inline linear thin table mount_options

        source="$(findmnt --noheadings --output SOURCE --target "/home/$user" | xargs)"
        source="${source%%\[*}"
        top="$(dmsetup info --columns --noheadings --options name "$source" | xargs)"
        [[ "$(dmsetup table "$top" | awk 'NR == 1 { print $3 }')" == integrity ]]
        inline="$(hw_dm_child "$top")"
        [[ -n "$inline" ]]
        [[ "$(dmsetup table "$inline" | awk 'NR == 1 { print $3 }')" == inlinecrypt ]]
        table="$(dmsetup table "$inline")"
        grep -w 'keytype:hw-wrapped' <<<"$table"
        ! grep -Eq '(^|[[:space:]])[[:xdigit:]]{64,}([[:space:]]|$)' <<<"$table"
        linear="$(hw_dm_child "$inline")"
        [[ "$(dmsetup table "$linear" | awk 'NR == 1 { print $3 }')" == linear ]]
        thin="$(hw_dm_child "$linear")"
        [[ "$(dmsetup table "$thin" | awk 'NR == 1 { print $3 }')" == thin ]]
        mount_options="$(findmnt --noheadings --output OPTIONS --target "/home/$user")"
        grep -w provision <<<"${mount_options//,/ }"
        grep -w nodelalloc <<<"${mount_options//,/ }"
    }

    hw_assert_allocation_and_trim() {
        local before allocated trimmed

        before="$(dmsetup status "$pool_name" | awk '{ print $6 }')"
        dd if=/dev/zero of="/home/$user/discard-me" bs=1M count=16 conv=fsync
        allocated="$(dmsetup status "$pool_name" | awk '{ print $6 }')"
        awk -v before="$before" -v after="$allocated" \
            'BEGIN { split(before, b, "/"); split(after, a, "/"); exit !(a[1] > b[1]) }'
        rm "/home/$user/discard-me"
        trimmed="$allocated"
        for _ in {1..20}; do
            fstrim "/home/$user"
            sync
            trimmed="$(dmsetup status "$pool_name" | awk '{ print $6 }')"
            if awk -v before="$allocated" -v after="$trimmed" \
                'BEGIN { split(before, b, "/"); split(after, a, "/"); exit !(a[1] < b[1]) }'; then
                break
            fi
            sleep 0.2
        done
        awk -v before="$allocated" -v after="$trimmed" \
            'BEGIN { split(before, b, "/"); split(after, a, "/"); exit !(a[1] < b[1]) }'
    }

    hw_header_hash() {
        dd if="$1" bs=1M count=32 status=none | sha256sum | awk '{ print $1 }'
    }

    case "$phase" in
        1)
            local machine_id record header_hash

            NEWPASSWORD="$password" homectl create "$user" \
                --storage=luks --fs-type=ext4 --disk-size=2G \
                --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms
            machine_id="$(cat /etc/machine-id)"
            record="$(homectl inspect --json=short "$user")"
            [[ "$(jq -er --arg m "$machine_id" '.binding[$m].luksKeyType' <<<"$record")" == hw-wrapped ]]
            [[ "$(jq -er --arg m "$machine_id" '.binding[$m].luksIntegrity' <<<"$record")" == 'hmac(sha256)' ]]
            home_uuid="$(jq -er '.uuid' <<<"$record")"
            thin_mapping="homed-${home_uuid//-/}"
            thin_device_id="$(jq -er --arg m "$machine_id" '.binding[$m].thinDeviceId' <<<"$record")"
            [[ "$(jq -er --arg m "$machine_id" '.binding[$m].thinPoolUuid' <<<"$record")" == "$pool_uuid" ]]
            luks_uuid="$(jq -er --arg m "$machine_id" '.binding[$m].luksUuid' <<<"$record")"
            hw_open_image
            hw_assert_metadata "$image_path"
            hw_close_image

            PASSWORD="$password" homectl activate "$user"
            hw_assert_topology
            printf '%s\n' 'persistent-wrapped-home-marker-7bcce8ef' >"/home/$user/persistent"
            sync
            hw_assert_allocation_and_trim
            homectl lock "$user"
            dmsetup info "home-$user" | grep -w SUSPENDED
            # The private lower mapping may lose its userspace name while a
            # deferred removal is pending. Unlock must still find it through
            # the upper mapping's device dependency.
            if ! PASSWORD="$password" homectl unlock "$user"; then
                journalctl --boot --no-pager --unit systemd-homed.service
                return 1
            fi
            PASSWORD="$password" NEWPASSWORD="$rotated" homectl passwd "$user"
            homectl deactivate "$user"
            hw_open_image
            header_hash="$(hw_header_hash "$image_path")"
            hw_close_image
            printf 'metadata_device=%q\ndata_device=%q\nhome_uuid=%q\nthin_mapping=%q\nthin_device_id=%q\nluks_uuid=%q\nheader_hash=%q\n' \
                "$metadata_device" "$data_device" "$home_uuid" "$thin_mapping" "$thin_device_id" \
                "$luks_uuid" "$header_hash" >"$state_file"
            printf 'HOMED_HW_WRAPPED_PHASE_1_PASS thin_device_id=%s\n' "$thin_device_id"
            ;;
        2)
            hw_open_image
            [[ "$(hw_header_hash "$image_path")" == "$header_hash" ]]
            hw_close_image
            if PASSWORD="$rotated" homectl activate "$user"; then
                echo "Wrapped home activated under the wrong hardware identity" >&2
                return 1
            fi
            hw_open_image
            [[ "$(hw_header_hash "$image_path")" == "$header_hash" ]]
            hw_close_image
            homectl inspect "$user" | grep -w inactive
            [[ ! -e "/home/$user/persistent" ]]
            ! dmsetup message "$pool_name" 0 "create_thin $thin_device_id"
            printf 'HOMED_HW_WRAPPED_PHASE_2_PASS thin_device_id=%s\n' "$thin_device_id"
            ;;
        3)
            hw_open_image
            hw_assert_metadata "$image_path"
            hw_close_image
            if PASSWORD=definitely-wrong homectl --no-ask-password activate "$user"; then
                echo "Wrapped home activated with the wrong password" >&2
                return 1
            fi
            PASSWORD="$rotated" homectl activate "$user"
            grep -Fx 'persistent-wrapped-home-marker-7bcce8ef' "/home/$user/persistent"
            hw_assert_topology
            hw_assert_allocation_and_trim
            homectl deactivate "$user"
            homectl remove "$user"
            ! dmsetup create "$thin_mapping" --table \
                "0 $((2 * 1024 * 1024 * 1024 / 512)) thin $pool $thin_device_id"
            dmsetup remove "$thin_mapping" || :
            rm -f "$state_file"
            dmsetup remove --retry "$pool_name"
            rm -f /var/lib/systemd/home/.thin-pool-state /var/lib/systemd/home/.thin-pool-state.lock
            printf 'HOMED_HW_WRAPPED_PHASE_3_PASS thin_device_id=%s\n' "$thin_device_id"
            ;;
    esac
}

run_testcases
