#!/usr/bin/env bash
set -ex
set -o pipefail

# Check if homectl is installed, and if it isn't bail out early instead of failing
if ! test -x /usr/bin/homectl ; then
        echo OK > /testok
        exit 0
fi

inspect() {
        # As updating disk-size-related attributes can take some time on
        # some filesystems, let's drop these fields before comparing the
        # outputs to avoid unexpected fails. To see the full outputs of both
        # homectl & userdbctl (for debugging purposes) drop the fields just
        # before the comparison.
        homectl inspect $1 | tee /tmp/a
        userdbctl user $1 | tee /tmp/b

        local PATTERN='/^\s*Disk (Size|Free|Floor|Ceiling):/d'
        diff <(sed -r "$PATTERN" /tmp/a) <(sed -r "$PATTERN" /tmp/b)
        rm /tmp/a /tmp/b
}

systemd-analyze log-level debug
systemd-analyze log-target console

NEWPASSWORD=xEhErW0ndafV4s homectl create test-user --disk-size=20M
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

! PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- touch /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz
PASSWORD=xEhErW0ndafV4s homectl with test-user -- rm /home/test-user/xyz
! PASSWORD=xEhErW0ndafV4s homectl with test-user -- test -f /home/test-user/xyz

homectl remove test-user

systemd-analyze log-level info

echo OK > /testok

exit 0
