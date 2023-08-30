#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

systemd-analyze log-level debug

export SYSTEMD_LOG_LEVEL=debug

if [ -f /run/testsuite82.touch3 ]; then
    echo "This is the fourth boot!"
    systemd-notify --status="Fourth Boot"

    rm /run/testsuite82.touch3
    mount
    rmdir /original-root /run/nextroot

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 3
    read -r x <&5
    test "$x" = "oinkoink"

    # Check that no service is still around
    test "$(systemctl show -P ActiveState testsuite-82-survive.service)" != "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive.service)" != "active"

    # All succeeded, exit cleanly now

elif [ -f /run/testsuite82.touch2 ]; then
    echo "This is the third boot!"
    systemd-notify --status="Third Boot"

    rm /run/testsuite82.touch2

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 2
    read -r x <&4
    test "$x" = "miaumiau"

    # Upload another entry
    T="/dev/shm/fdstore.$RANDOM"
    echo "oinkoink" >"$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # Check that no service is still around
    test "$(systemctl show -P ActiveState testsuite-82-survive.service)" != "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive.service)" != "active"

    # Test that we really are in the new overlayfs root fs
    read -r x </lower
    test "$x" = "miep"
    cmp /etc/os-release /run/systemd/propagate/.os-release-stage/os-release
    grep -q MARKER=1 /etc/os-release

    # Switch back to the original root, away from the overlayfs
    mount --bind /original-root /run/nextroot
    mount

    # Now issue the soft reboot. We should be right back soon.
    touch /run/testsuite82.touch3
    systemctl --no-block soft-reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity

elif [ -f /run/testsuite82.touch ]; then
    echo "This is the second boot!"
    systemd-notify --status="Second Boot"

    # Clean up what we created earlier
    rm /run/testsuite82.touch

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 1
    read -r x <&3
    test "$x" = "wuffwuff"

    # Check that we got a PrepareForShutdownWithMetadata signal with the right type
    test "$(jq .payload.data[1].type.data </run/testsuite82.signal)" = "\"soft-reboot\""

    # Upload another entry
    T="/dev/shm/fdstore.$RANDOM"
    echo "miaumiau" >"$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # Check that no service survived, regardless of the configuration
    test "$(systemctl show -P ActiveState testsuite-82-survive.service)" != "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive.service)" != "active"

    # This time we test the /run/nextroot/ root switching logic. (We synthesize a new rootfs from the old via overlayfs)
    mkdir -p /run/nextroot /tmp/nextroot-lower /original-root
    mount -t tmpfs tmpfs /tmp/nextroot-lower
    echo miep >/tmp/nextroot-lower/lower

    # Copy os-release away, so that we can manipulate it and check that it is updated in the propagate
    # directory across soft reboots. Try to cover corner cases by truncating it.
    mkdir -p /tmp/nextroot-lower/usr/lib
    grep ID /etc/os-release >/tmp/nextroot-lower/usr/lib/os-release
    echo MARKER=1 >>/tmp/nextroot-lower/usr/lib/os-release
    cmp /etc/os-release /run/systemd/propagate/.os-release-stage/os-release
    (! grep -q MARKER=1 /etc/os-release)

    mount -t overlay nextroot /run/nextroot -o lowerdir=/tmp/nextroot-lower:/,ro

    # Bind our current root into the target so that we later can return to it
    mount --bind / /run/nextroot/original-root

    # Now issue the soft reboot. We should be right back soon.
    touch /run/testsuite82.touch2
    systemctl --no-block soft-reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity
else
    # This is the first boot
    systemd-notify --status="First Boot"

    # Let's upload an fd to the fdstore, so that we can verify fdstore passing works correctly
    T="/dev/shm/fdstore.$RANDOM"
    echo "wuffwuff" >"$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # Create a script that can survive the soft reboot by ignoring SIGTERM (we
    # do this instead of the argv[0][0] = '@' thing because that's so hard to
    # do from a shell
    T="/dev/shm/survive-$RANDOM.sh"
    cat >$T <<EOF
#!/bin/bash
trap "" TERM
systemd-notify --ready
rm "$T"
exec sleep infinity
EOF
    chmod +x "$T"
    # This sets DefaultDependencies=no so that it remains running until the
    # very end, and IgnoreOnIsolate=yes so that it isn't stopped via the
    # "testsuite.target" isolation we do on next boot
    systemd-run -p Type=notify -p DefaultDependencies=no -p IgnoreOnIsolate=yes --unit=testsuite-82-survive.service "$T"
    systemd-run -p Type=exec -p DefaultDependencies=no -p IgnoreOnIsolate=yes --unit=testsuite-82-nosurvive.service sleep infinity

    # Check that we can set up an inhibitor, and that busctl monitor sees the
    # PrepareForShutdownWithMetadata signal and that it says 'soft-reboot'.
    systemd-run --unit busctl.service --property StandardOutput=file:/run/testsuite82.signal \
        busctl monitor --json=pretty --match 'sender=org.freedesktop.login1,path=/org/freedesktop/login1,interface=org.freedesktop.login1.Manager,member=PrepareForShutdownWithMetadata,type=signal'
    systemd-run --unit inhibit.service \
        systemd-inhibit --what=shutdown --who=test --why=test --mode=delay \
            sleep infinity

    # Now issue the soft reboot. We should be right back soon.
    touch /run/testsuite82.touch
    systemctl --no-block --check-inhibitors=yes soft-reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity
fi

systemd-analyze log-level info

touch /testok
systemctl --no-block poweroff
