#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

systemd-analyze log-level debug

export SYSTEMD_LOG_LEVEL=debug

if [ -f /run/testsuite82.touch ] ; then
    systemd-notify --status="Second Boot"

    # This is the second boot
    rm /run/testsuite82.touch

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 1
    read x <&3
    test "$x" = "wuffwuff"

else
    systemd-notify --status="First Boot"


    # This is the first boot, lte's upload an fd to the fdstore
    T="/dev/shm/fdstore.$RANDOM"
    echo "wuffwuff" > "$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # Now issue the soft reboot. We should be right back soon.
    touch /run/testsuite82.touch
    systemctl --no-block soft-reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity
fi

systemd-analyze log-level info
echo OK >/testok

systemctl --no-block poweroff

exit 0
