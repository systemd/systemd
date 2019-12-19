#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug

runas() {
    declare userid=$1
    shift
    su "$userid" -c 'XDG_RUNTIME_DIR=/run/user/$UID "$@"' -- sh "$@"
}

runas nobody systemctl --user --wait is-system-running

runas nobody systemd-run --user --unit=test-private-users \
    -p PrivateUsers=yes -P echo hello

runas nobody systemd-run --user --unit=test-private-tmp-innerfile \
    -p PrivateUsers=yes -p PrivateTmp=yes \
    -P touch /tmp/innerfile.txt
# File should not exist outside the job's tmp directory.
test ! -e /tmp/innerfile.txt

touch /tmp/outerfile.txt
# File should not appear in unit's private tmp.
runas nobody systemd-run --user --unit=test-private-tmp-outerfile \
    -p PrivateUsers=yes -p PrivateTmp=yes \
    -P test ! -e /tmp/outerfile.txt

# Confirm that creating a file in home works
runas nobody systemd-run --user --unit=test-unprotected-home \
    -P touch /home/nobody/works.txt
test -e /home/nobody/works.txt

# Confirm that creating a file in home is blocked under read-only
runas nobody systemd-run --user --unit=test-protect-home-read-only \
    -p PrivateUsers=yes -p ProtectHome=read-only \
    -P bash -c '
        test -e /home/nobody/works.txt
        ! touch /home/nobody/blocked.txt
    '
test ! -e /home/nobody/blocked.txt

# Check that tmpfs hides the whole directory
runas nobody systemd-run --user --unit=test-protect-home-tmpfs \
    -p PrivateUsers=yes -p ProtectHome=tmpfs \
    -P test ! -e /home/nobody

# Confirm that home, /root, and /run/user are inaccessible under "yes"
runas nobody systemd-run --user --unit=test-protect-home-yes \
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
! runas nobody systemd-run --user --unit=test-group-fail \
    -p PrivateUsers=yes -p Group=daemon \
    -P true

systemd-analyze log-level info

echo OK > /testok

exit 0
