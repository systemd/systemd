#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check if homectl is installed, and if it isn't bail out early instead of failing
if ! test -x /usr/bin/homectl ; then
        echo OK >/testok
        exit 0
fi

inspect() {
    # As updating disk-size-related attributes can take some time on some
    # filesystems, let's drop these fields before comparing the outputs to
    # avoid unexpected fails. To see the full outputs of both homectl &
    # userdbctl (for debugging purposes) drop the fields just before the
    # comparison.
    local USERNAME="${1:?missing argument}"
    homectl inspect "$USERNAME" | tee /tmp/a
    userdbctl user "$USERNAME" | tee /tmp/b

    # diff uses the grep BREs for pattern matching
    diff -I '^\s*Disk \(Size\|Free\|Floor\|Ceiling\):' /tmp/{a,b}
    rm /tmp/{a,b}
}

systemd-analyze log-level debug
systemd-analyze log-target console

# Create a tmpfs to use as backing store for the home dir. That way we can enforce a size limit nicely.
mkdir -p /home-pool
mount -t tmpfs tmpfs /home-pool -o size=290M

# we enable --luks-discard= since we run our tests in a tight VM, hence don't
# needlessly pressure for storage. We also set the cheapest KDF, since we don't
# want to waste CI CPU cycles on it.
NEWPASSWORD=xEhErW0ndafV4s homectl create test-user \
           --disk-size=256M \
           --luks-discard=yes \
           --image-path=/home-pool/test-user.home \
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

PASSWORD=xEhErW0ndafV4s homectl deactivate test-user
inspect test-user

PASSWORD=xEhErW0ndafV4s homectl update test-user --real-name="Offline test"
inspect test-user

PASSWORD=xEhErW0ndafV4s homectl activate test-user
inspect test-user

PASSWORD=xEhErW0ndafV4s homectl deactivate test-user
inspect test-user

# Do some resize tests, but only if we run on real kernels, as quota inside of containers will fail
if ! systemd-detect-virt -cq ; then
    # grow while inactive
    PASSWORD=xEhErW0ndafV4s homectl resize test-user 300M
    inspect test-user

    # minimize while inactive
    PASSWORD=xEhErW0ndafV4s homectl resize test-user 0
    inspect test-user

    PASSWORD=xEhErW0ndafV4s homectl activate test-user
    inspect test-user

    # grow while active
    PASSWORD=xEhErW0ndafV4s homectl resize test-user 1T
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

    PASSWORD=xEhErW0ndafV4s homectl deactivate test-user
    inspect test-user
fi

PASSWORD=xEhErW0ndafV4s homectl with test-user -- test ! -f /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz \
    && { echo 'unexpected success'; exit 1; }
PASSWORD=xEhErW0ndafV4s homectl with test-user -- touch /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- rm /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test ! -f /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz \
    && { echo 'unexpected success'; exit 1; }

homectl remove test-user

systemd-analyze log-level info

echo OK >/testok

exit 0
