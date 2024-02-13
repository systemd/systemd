#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check if homectl is installed, and if it isn't bail out early instead of failing
if ! test -x /usr/bin/homectl ; then
        echo "no homed" >/skipped
        exit 0
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
    diff -I '^\s*Disk \(Size\|Free\|Floor\|Ceiling\):' /tmp/{a,b}
    rm /tmp/{a,b}

    homectl inspect --json=pretty "$USERNAME"
}

wait_for_state() {
    for i in {1..10}; do
        (( i > 1 )) && sleep 0.5
        homectl inspect "$1" | grep -qF "State: $2" && break
    done
}

systemd-analyze log-level debug
systemctl service-log-level systemd-homed debug

# Create a tmpfs to use as backing store for the home dir. That way we can enforce a size limit nicely.
mkdir -p /home
mount -t tmpfs tmpfs /home -o size=290M

# we enable --luks-discard= since we run our tests in a tight VM, hence don't
# needlessly pressure for storage. We also set the cheapest KDF, since we don't
# want to waste CI CPU cycles on it.
NEWPASSWORD=xEhErW0ndafV4s homectl create test-user \
           --disk-size=min \
           --luks-discard=yes \
           --image-path=/home/test-user.home \
           --luks-pbkdf-type=pbkdf2 \
           --luks-pbkdf-time-cost=1ms
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

# Do some resize tests, but only if we run on real kernels, as quota inside of containers will fail
if ! systemd-detect-virt -cq ; then
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
    NEWPASSWORD=uuXoo8ei homectl create test-user2 \
           --disk-size=min \
           --luks-discard=yes \
           --image-path=/home/test-user2.home \
           --luks-pbkdf-type=pbkdf2 \
           --luks-pbkdf-time-cost=1ms
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
fi

# Do some keyring tests, but only on real kernels, since keyring access inside of containers will fail
# (See: https://github.com/systemd/systemd/issues/17606)
if ! systemd-detect-virt -cq ; then
        PASSWORD=xEhErW0ndafV4s homectl activate test-user
        inspect test-user

        # Key should now be in the keyring
        homectl update test-user --real-name "Keyring Test"
        inspect test-user

        # These commands shouldn't use the keyring
        (! homectl authenticate test-user </dev/null )
        (! NEWPASSWORD="foobar" homectl passwd test-user </dev/null )

        homectl lock test-user
        inspect test-user

        # Key should be gone from keyring
        (! homectl update test-user --real-name "Keyring Test 2" </dev/null )

        PASSWORD=xEhErW0ndafV4s homectl unlock test-user
        inspect test-user

        # Key should have been re-instantiated into the keyring
        homectl update test-user --real-name "Keyring Test 3"
        inspect test-user

        homectl deactivate test-user
        inspect test-user
fi

PASSWORD=xEhErW0ndafV4s homectl with test-user -- test ! -f /home/test-user/xyz
(! PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz)
PASSWORD=xEhErW0ndafV4s homectl with test-user -- touch /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz
# CAREFUL adding more `homectl with` tests here. Auth can get rate-limited and cause the tests to fail.

wait_for_state test-user inactive
homectl remove test-user

if ! systemd-detect-virt -cq ; then
    wait_for_state test-user2 active
    homectl deactivate test-user2
    wait_for_state test-user2 inactive
    homectl remove test-user2
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
echo data1 blob1 > /tmp/blob1/test1
echo data1 blob2 > /tmp/blob2/test1
echo data2 blob1 > /tmp/blob1/test2
echo data2 blob2 > /tmp/blob2/test2
echo invalid filename > /tmp/blob1/файл
ln -s /tmp/blob1/test1 /tmp/blob1/symlink
echo data3 > /tmp/external-test3
echo avatardata > /tmp/external-avatar
ln -s /tmp/external-avatar /tmp/external-avatar-lnk
dd if=/dev/urandom of=/tmp/external-barely-fits bs=1M count=64
dd if=/dev/urandom of=/tmp/external-toobig bs=1M count=65

# create w/ prepopulated blob dir
NEWPASSWORD=EMJuc3zQaMibJo homectl create blob-user \
           --disk-size=min --luks-discard=yes \
           --luks-pbkdf-type=pbkdf2 --luks-pbkdf-time-cost=1ms \
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
(! checkblob symlink /tmp/blob1/symlink )
(! checkblob test3 /tmp/external-test3 )
(! checkblob avatar /tmp/external-avatar )

# append files to existing blob, both well-known and other
PASSWORD=EMJuc3zQaMibJo homectl update blob-user \
        -b test3=/tmp/external-test3 --avatar=/tmp/external-avatar
inspect blob-user
checkblob test1 /tmp/blob1/test1
(! checkblob test1 /tmp/blob2/test1 )
checkblob test2 /tmp/blob1/test2
(! checkblob test2 /tmp/blob2/test2 )
(! checkblob фаил /tmp/blob1/фаил )
(! checkblob symlink /tmp/blob1/symlink )
checkblob test3 /tmp/external-test3
checkblob avatar /tmp/external-avatar

# delete files from existing blob, both well-known and other
PASSWORD=EMJuc3zQaMibJo homectl update blob-user \
        -b test3= --avatar=
inspect blob-user
checkblob test1 /tmp/blob1/test1
(! checkblob test1 /tmp/blob2/test1 )
checkblob test2 /tmp/blob1/test2
(! checkblob test2 /tmp/blob2/test2 )
(! checkblob фаил /tmp/blob1/фаил )
(! checkblob symlink /tmp/blob1/symlink )
(! checkblob test3 /tmp/external-test3 )
(! checkblob avatar /tmp/external-avatar )

# swap entire blob directory
PASSWORD=EMJuc3zQaMibJo homectl update blob-user \
        -b /tmp/blob2
inspect blob-user
(! checkblob test1 /tmp/blob1/test1 )
checkblob test1 /tmp/blob2/test1
(! checkblob test2 /tmp/blob1/test2 )
checkblob test2 /tmp/blob2/test2
(! checkblob фаил /tmp/blob1/фаил )
(! checkblob symlink /tmp/blob1/symlink )
(! checkblob test3 /tmp/external-test3 )
(! checkblob avatar /tmp/external-avatar )

# create and delete files while swapping blob directory. Also symlinks.
PASSWORD=EMJuc3zQaMibJo homectl update blob-user \
        -b /tmp/blob1 -b test2= -b test3=/tmp/external-test3 --avatar=/tmp/external-avatar-lnk
inspect blob-user
checkblob test1 /tmp/blob1/test1
(! checkblob test1 /tmp/blob2/test1 )
(! checkblob test2 /tmp/blob1/test2 )
(! checkblob test2 /tmp/blob2/test2 )
(! checkblob фаил /tmp/blob1/фаил )
(! checkblob symlink /tmp/blob1/symlink )
checkblob test3 /tmp/external-test3
checkblob avatar /tmp/external-avatar # target of the link

# clear the blob directory
PASSWORD=EMJuc3zQaMibJo homectl update blob-user \
        -b /tmp/blob2 -b test3=/tmp/external-test3 --blob=
inspect blob-user
(! checkblob test1 /tmp/blob1/test1 )
(! checkblob test1 /tmp/blob2/test1 )
(! checkblob test2 /tmp/blob1/test2 )
(! checkblob test2 /tmp/blob2/test2 )
(! checkblob фаил /tmp/blob1/фаил )
(! checkblob symlink /tmp/blob1/symlink )
(! checkblob test3 /tmp/external-test3 )
(! checkblob avatar /tmp/external-avatar )

# file that's exactly 64M still fits
PASSWORD=EMJuc3zQaMibJo homectl update blob-user \
        -b barely-fits=/tmp/external-barely-fits
(! checkblob test1 /tmp/blob1/test1 )
(! checkblob test1 /tmp/blob2/test1 )
(! checkblob test2 /tmp/blob1/test2 )
(! checkblob test2 /tmp/blob2/test2 )
(! checkblob фаил /tmp/blob1/фаил )
(! checkblob symlink /tmp/blob1/symlink )
(! checkblob test3 /tmp/external-test3 )
(! checkblob avatar /tmp/external-avatar )
checkblob barely-fits /tmp/external-barely-fits

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
homectl update blob-user --offline -b propagated=/tmp/external-test3
inspect blob-user
PASSWORD=EMJuc3zQaMibJo homectl activate blob-user
inspect-blob-user
checkblob propagated /tmp/external-test3

homectl deactivate blob-user
wait_for_state blob-user inactive
homectl remove blob-user

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
userdbctl ssh-authorized-keys dropinuser --chain /bin/cat /tmp/my-top-secret-key | tee /tmp/authorized-keys
grep "ssh-ed25519" /tmp/authorized-keys
grep "ecdsa-sha2-nistp256" /tmp/authorized-keys
grep "my-top-secret-key 🐱" /tmp/authorized-keys
(! userdbctl ssh-authorized-keys 🐱)
(! userdbctl ssh-authorized-keys dropin-user --chain)
(! userdbctl ssh-authorized-keys dropin-user --chain '')
(! SYSTEMD_LOG_LEVEL=debug userdbctl ssh-authorized-keys dropin-user --chain /bin/false)

(! userdbctl '')
for opt in json multiplexer output synthesize with-dropin with-nss with-varlink; do
    (! userdbctl "--$opt=''")
    (! userdbctl "--$opt='🐱'")
    (! userdbctl "--$opt=foo")
    (! userdbctl "--$opt=foo" "--$opt=''" "--$opt=🐱")
done

systemd-analyze log-level info

touch /testok
