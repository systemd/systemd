#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

systemd-analyze log-level debug

export SYSTEMD_LOG_LEVEL=debug

if [ -f /run/testsuite82.touch3 ] ; then
    echo "This is the fourth boot!"
    systemd-notify --status="Fourth Boot"

    rm /run/testsuite82.touch3
    rmdir /original-root /run/nextroot

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 3
    read -r x <&5
    test "$x" = "oinkoink"

    # All succeeded, exit cleanly now

elif [ -f /run/testsuite82.touch2 ] ; then
    echo "This is the third boot!"
    systemd-notify --status="Third Boot"

    rm /run/testsuite82.touch2

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 2
    read -r x <&4
    test "$x" = "miaumiau"

    # Upload another entry
    T="/dev/shm/fdstore.$RANDOM"
    echo "oinkoink" > "$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # Test that we really are in the new overlayfs root fs
    read -r x </lower
    test "$x" = "miep"

    # Switch back to the original root, away from the overlayfs
    mount --bind /original-root /run/nextroot -o x-initrd.mount

    # Now issue the soft reboot. We should be right back soon.
    touch /run/testsuite82.touch3
    systemctl --no-block soft-reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity

elif [ -f /run/testsuite82.touch ] ; then
    echo "This is the second boot!"
    systemd-notify --status="Second Boot"

    # Clean up what we created earlier
    rm /run/testsuite82.touch

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 1
    read -r x <&3
    test "$x" = "wuffwuff"

    # Upload another entry
    T="/dev/shm/fdstore.$RANDOM"
    echo "miaumiau" > "$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # This time we test the /run/nextroot/ root switching logic. (We synthesize a new rootfs from the old via overlayfs)
    mkdir -p /run/nextroot /tmp/nextroot-lower /original-root
    mount -t tmpfs tmpfs /tmp/nextroot-lower
    echo miep > /tmp/nextroot-lower/lower
    mount -t overlay nextroot /run/nextroot -o lowerdir=/:/tmp/nextroot-lower,ro,x-initrd.mount

    # Bind our current root into the target so that we later can return to it
    mount --bind / /run/nextroot/original-root -o x-initrd.mount

    # Now issue the soft reboot. We should be right back soon.
    touch /run/testsuite82.touch2
    systemctl --no-block soft-reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity
else
    # This is the first boot
    systemd-notify --status="First Boot"

    # Let's upload an fd to the fdstore, so that we can verify fdstore passing works correcly
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
