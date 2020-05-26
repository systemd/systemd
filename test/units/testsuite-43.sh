#!/usr/bin/env bash
set -ex
set -o pipefail

systemd-analyze log-level debug

runas() {
    declare userid=$1
    shift
    su "$userid" -s /bin/sh -c 'XDG_RUNTIME_DIR=/run/user/$UID exec "$@"' -- sh "$@"
}

runas testuser systemd-run --wait --user --unit=test-private-users \
    -p PrivateUsers=yes -P echo hello

runas testuser systemd-run --wait --user --unit=test-private-tmp-innerfile \
    -p PrivateUsers=yes -p PrivateTmp=yes \
    -P touch /tmp/innerfile.txt
# File should not exist outside the job's tmp directory.
test ! -e /tmp/innerfile.txt

touch /tmp/outerfile.txt
# File should not appear in unit's private tmp.
runas testuser systemd-run --wait --user --unit=test-private-tmp-outerfile \
    -p PrivateUsers=yes -p PrivateTmp=yes \
    -P test ! -e /tmp/outerfile.txt

# Confirm that creating a file in home works
runas testuser systemd-run --wait --user --unit=test-unprotected-home \
    -P touch /home/testuser/works.txt
test -e /home/testuser/works.txt

# Confirm that creating a file in home is blocked under read-only
runas testuser systemd-run --wait --user --unit=test-protect-home-read-only \
    -p PrivateUsers=yes -p ProtectHome=read-only \
    -P bash -c '
        test -e /home/testuser/works.txt
        ! touch /home/testuser/blocked.txt
    '
test ! -e /home/testuser/blocked.txt

# Check that tmpfs hides the whole directory
runas testuser systemd-run --wait --user --unit=test-protect-home-tmpfs \
    -p PrivateUsers=yes -p ProtectHome=tmpfs \
    -P test ! -e /home/testuser

# Confirm that home, /root, and /run/user are inaccessible under "yes"
runas testuser systemd-run --wait --user --unit=test-protect-home-yes \
    -p PrivateUsers=yes -p ProtectHome=yes \
    -P bash -c '
        test "$(stat -c %a /home)" = "0"
        test "$(stat -c %a /root)" = "0"
        test "$(stat -c %a /run/user)" = "0"
    '

# Confirm we cannot change groups because we only have one mapping in the user
# namespace (no CAP_SETGID in the parent namespace to write the additional
# mapping of the user supplied group and thus cannot change groups to an
# unmapped group ID)
! runas testuser systemd-run --wait --user --unit=test-group-fail \
    -p PrivateUsers=yes -p Group=daemon \
    -P true

systemd-analyze log-level info

echo OK > /testok

exit 0
