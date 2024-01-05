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

PASSWORD=xEhErW0ndafV4s homectl activate test-user
inspect test-user

homectl deactivate test-user
inspect test-user

PASSWORD=xEhErW0ndafV4s homectl update test-user --real-name="Offline test"
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

PASSWORD=xEhErW0ndafV4s homectl with test-user -- test ! -f /home/test-user/xyz
(! PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz)
PASSWORD=xEhErW0ndafV4s homectl with test-user -- touch /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- rm /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test ! -f /home/test-user/xyz
(! PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz)

wait_for_state test-user inactive
homectl remove test-user

if ! systemd-detect-virt -cq ; then
    wait_for_state test-user2 active
    homectl deactivate test-user2
    wait_for_state test-user2 inactive
    homectl remove test-user2
fi

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

# Test that SSH logins work with delayed unlocking
ssh-keygen -N '' -C '' -t rsa -f /tmp/homed.id_rsa
NEWPASSWORD=hunter4711 homectl create \
                       --disk-size=min \
                       --luks-discard=yes \
                       --luks-pbkdf-type=pbkdf2 \
                       --luks-pbkdf-time-cost=1ms \
                       --enforce-password-policy=no \
                       --ssh-authorized-keys=@/tmp/homed.id_rsa.pub \
                       --stop-delay=0 \
                       homedsshtest

mkdir -p /etc/ssh
test -f /etc/ssh/ssh_host_rsa_key || ssh-keygen -t rsa -C '' -N '' -f /etc/ssh/ssh_host_rsa_key

# ssh wants this dir around, but distros cannot agree on a common name for it, let's just create all that are aware of distros use
mkdir -p /usr/share/empty.sshd /var/empty /var/empty/sshd

cat >> /etc/ssh/sshd_config <<EOF
AuthorizedKeysCommand /usr/bin/userdbctl ssh-authorized-keys %u
AuthorizedKeysCommandUser root
UsePAM yes
AcceptEnv PASSWORD
EOF

cat > /run/systemd/system/mysshserver.socket <<EOF
[Socket]
ListenStream=4711
Accept=yes
EOF

cat > /run/systemd/system/mysshserver@.service <<EOF
[Service]
ExecStart=-/usr/sbin/sshd -i -d -e
StandardInput=socket
StandardOutput=socket
StandardError=journal
EOF

systemctl daemon-reload
systemctl start mysshserver.socket

userdbctl user -j homedsshtest

ssh -t -t -4 -p 4711 -i /tmp/homed.id_rsa -o "SetEnv PASSWORD=hunter4711" -o "StrictHostKeyChecking no" homedsshtest@localhost echo zzz | tail -n 1 | tr -d '\r' > /tmp/homedsshtest.out
cat /tmp/homedsshtest.out
test "$(cat /tmp/homedsshtest.out)" = "zzz"
rm /tmp/homedsshtest.out

ssh -t -t -4 -p 4711 -i /tmp/homed.id_rsa -o "SetEnv PASSWORD=hunter4711" -o "StrictHostKeyChecking no" homedsshtest@localhost env

wait_for_state homedsshtest inactive
homectl remove homedsshtest

systemctl stop mysshserver.socket
rm /run/systemd/system/mysshserver.socket
rm /run/systemd/system/mysshserver@.service

systemd-analyze log-level info

touch /testok
