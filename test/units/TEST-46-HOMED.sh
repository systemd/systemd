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
    timeout 2m bash -c "until homectl inspect '${1:?}' | grep -qF 'State: $2'; do sleep 2; done"
}

get_uid() {
    local uid name="${1:?}"

    # The machine ID may start with a numeric, and in that case the field name must be quoted.
    uid="$(homectl inspect --json=short "$name" | jq .binding.\""$(cat /etc/machine-id)"\".uid)"

    # Check if the obtained UID is consistent with the one provided by the id command.
    # Note, this requires systemd NSS module.
    if check_nss_module systemd; then
        [[ "$(id -u "$name")" == "$uid" ]]
    fi

    echo "$uid"
}

FSTYPE="$(stat --file-system --format "%T" /)"

systemctl start systemd-homed.service systemd-userdbd.socket

# Create a tmpfs to use as backing store for the home dir. That way we can enforce a size limit nicely.
mkdir -p /home
mount -t tmpfs tmpfs /home -o size=290M

# Make sure systemd-homed takes notice of the overmounted /home/
systemctl kill -sUSR1 systemd-homed

testcase_basic() {
    local TMP_SKEL

    . /etc/os-release
    if [[ "${ID_LIKE:-}" == alpine ]] && ! systemd-detect-virt -cq; then
        # luks seems to be broken on alpine/postmarketos.
        return 0
    fi

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
    fi
    [[ "$(PASSWORD=xEhErW0ndafV4s homectl with test-user -- stat -c %u /home/test-user/hoge)" == "$(get_uid test-user)" ]]
    [[ "$(PASSWORD=xEhErW0ndafV4s homectl with test-user -- cat /home/test-user/hoge)" == "$(cat "$TMP_SKEL"/hoge)" ]]

    # Regression tests
    wait_for_state test-user inactive
    /usr/lib/systemd/tests/unit-tests/manual/test-homed-regression-31896 test-user

    wait_for_state test-user inactive
    homectl remove test-user
}

testcase_blob() {
    . /etc/os-release
    if [[ "${ID_LIKE:-}" == alpine ]] && ! systemd-detect-virt -cq; then
        # luks seems to be broken on alpine/postmarketos.
        return 0
    fi

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
    wait_for_state homedsshtest inactive
    homectl remove homedsshtest
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
        if findmnt -n -o options "$p" | grep -q usrquota; then
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

    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest sh -c 'echo $HOME')" = "/home/subareatest"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest sh -c 'echo x$XDG_AREA')" = "x"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $HOME')" = "/home/subareatest/Areas/furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $XDG_AREA')" = "furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/furb"

    PASSWORD=quux homectl update subareatest --default-area=molb
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest sh -c 'echo $HOME')" = "/home/subareatest/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest sh -c 'echo $XDG_AREA')" = "molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $HOME')" = "/home/subareatest/Areas/furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $XDG_AREA')" = "furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/furb"

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
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb sh -c 'echo $HOME')" = "/home/subareatest/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb sh -c 'echo $XDG_AREA')" = "molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/molb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $HOME')" = "/home/subareatest/Areas/furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $XDG_AREA')" = "furb"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=molb run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=furb sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/furb"

    # Test symlinked area
    mkdir -p /home/srub
    chown subareatest:subareatest /home/srub
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=srub sh -c 'echo $HOME')" = "/home/srub"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=srub sh -c 'echo $XDG_AREA')" = "srub"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=srub sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)/Areas/srub"

    # Verify that login into an area not owned by target user will be redirected to main area
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=root sh -c 'echo $HOME')" = "/home/subareatest"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=root sh -c 'echo x$XDG_AREA')" = "x"
    test "$(run0 --property=SetCredential=pam.authtok.systemd-run0:quux -u subareatest --area=root sh -c 'echo $XDG_RUNTIME_DIR')" = "/run/user/$(id -u subareatest)"

    systemctl stop user@"$(id -u subareatest)".service

    wait_for_state subareatest inactive
    homectl remove subareatest
}

testcase_sign() {
    # Test signing key logic
    homectl list-signing-keys | grep -q local.public
    (! (homectl list-signing-keys | grep -q signtest.public))

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
    homectl list-signing-keys | grep -q local.public
    homectl list-signing-keys | grep -q signtest.public

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
    homectl list-signing-keys | grep -q local.public
    (! (homectl list-signing-keys | grep -q signtest.public))

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
    (! (homectl list-signing-keys | grep -q signtest.public))
    systemd-run --wait -p "SetCredential=home.add-signing-key.signtest.public:$(print_public_key)" homectl firstboot
    homectl list-signing-keys | grep -q signtest.public

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

run_testcases
