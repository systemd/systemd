#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    # Since the soft-reboot drops the enqueued end.service, we won't shutdown
    # the test VM if the test fails and have to wait for the watchdog to kill
    # us (which may take quite a long time). Let's just forcibly kill the machine
    # instead to save CI resources.
    if [[ $? -ne 0 ]]; then
        echo >&2 "Test failed, shutting down the machine..."
        systemctl poweroff -ff
    fi
}

trap at_exit EXIT

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

    # Check that the surviving services are still around
    test "$(systemctl show -P ActiveState testsuite-82-survive.service)" = "active"
    test "$(systemctl show -P ActiveState testsuite-82-survive-argv.service)" = "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive-sigterm.service)" != "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive.service)" != "active"

    # Check journals
    journalctl -o short-monotonic --no-hostname --grep '(will soft-reboot|KILL|corrupt)'
    assert_eq "$(journalctl -q -o short-monotonic -u systemd-journald.service --grep 'corrupt')" ""

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

    # Check that the surviving services are still around
    test "$(systemctl show -P ActiveState testsuite-82-survive.service)" = "active"
    test "$(systemctl show -P ActiveState testsuite-82-survive-argv.service)" = "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive-sigterm.service)" != "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive.service)" != "active"

    # Test that we really are in the new overlayfs root fs
    read -r x </lower
    test "$x" = "miep"
    cmp /etc/os-release /run/systemd/propagate/.os-release-stage/os-release
    grep -q MARKER=1 /etc/os-release

    # Switch back to the original root, away from the overlayfs
    mount --bind /original-root /run/nextroot
    mount

    # Restart the unit that is not supposed to survive
    systemd-run --collect --service-type=exec --unit=testsuite-82-nosurvive.service sleep infinity

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
    cat /run/testsuite82.signal
    test "$(jq -r '.payload.data[1].type.data' </run/testsuite82.signal)" = "soft-reboot"

    # Upload another entry
    T="/dev/shm/fdstore.$RANDOM"
    echo "miaumiau" >"$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # Check that the surviving services are still around
    test "$(systemctl show -P ActiveState testsuite-82-survive.service)" = "active"
    test "$(systemctl show -P ActiveState testsuite-82-survive-argv.service)" = "active"
    test "$(systemctl show -P ActiveState testsuite-82-nosurvive-sigterm.service)" != "active"
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

    # Restart the unit that is not supposed to survive
    systemd-run --collect --service-type=exec --unit=testsuite-82-nosurvive.service sleep infinity

    # Now issue the soft reboot. We should be right back soon. Given /run/nextroot exists, we should
    # automatically do a softreboot instead of normal reboot.
    touch /run/testsuite82.touch2
    systemctl --no-block reboot

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

    survive_sigterm="/dev/shm/survive-sigterm-$RANDOM.sh"
    cat >"$survive_sigterm" <<EOF
#!/bin/bash
trap "" TERM
systemd-notify --ready
rm "$survive_sigterm"
exec sleep infinity
EOF
    chmod +x "$survive_sigterm"

    survive_argv="/dev/shm/survive-argv-$RANDOM.sh"
    cat >"$survive_argv" <<EOF
#!/bin/bash
systemd-notify --ready
rm "$survive_argv"
exec -a @sleep sleep infinity
EOF
    chmod +x "$survive_argv"
    # This sets DefaultDependencies=no so that they remain running until the very end, and
    # IgnoreOnIsolate=yes so that they aren't stopped via the "testsuite.target" isolation we do on next boot,
    # and will be killed by the final sigterm/sigkill spree.
    systemd-run --collect --service-type=notify -p DefaultDependencies=no -p IgnoreOnIsolate=yes --unit=testsuite-82-nosurvive-sigterm.service "$survive_sigterm"
    systemd-run --collect --service-type=exec -p DefaultDependencies=no -p IgnoreOnIsolate=yes --unit=testsuite-82-nosurvive.service sleep infinity

    # Ensure that the unit doesn't get deactivated by dependencies on the source file. Given it's a verity
    # image that is already open, even if the tmpfs with the image goes away, the file will be pinned by the
    # kernel and will keep working.
    cp /usr/share/minimal_0.* /tmp/

    # Configure these transient units to survive the soft reboot - they will not conflict with shutdown.target
    # and it will be ignored on the isolate that happens in the next boot. The first will use argv[0][0] =
    # '@', and the second will use SurviveFinalKillSignal=yes. Both should survive.
    systemd-run --service-type=notify --unit=testsuite-82-survive-argv.service \
        --property SurviveFinalKillSignal=no \
        --property IgnoreOnIsolate=yes \
        --property DefaultDependencies=no \
        --property After=basic.target \
        --property "Conflicts=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
        --property "Before=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
         "$survive_argv"
    systemd-run --service-type=exec --unit=testsuite-82-survive.service \
        --property TemporaryFileSystem="/run /tmp /var" \
        --property RootImage=/tmp/minimal_0.raw \
        --property BindReadOnlyPaths=/dev/log \
        --property BindReadOnlyPaths=/run/systemd/journal/socket \
        --property BindReadOnlyPaths=/run/systemd/journal/stdout \
        --property SurviveFinalKillSignal=yes \
        --property IgnoreOnIsolate=yes \
        --property DefaultDependencies=no \
        --property After=basic.target \
        --property "Conflicts=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
        --property "Before=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
        sleep infinity

    # Check that we can set up an inhibitor, and that busctl monitor sees the
    # PrepareForShutdownWithMetadata signal and that it says 'soft-reboot'.
    systemd-run --unit busctl.service --service-type=exec --property StandardOutput=file:/run/testsuite82.signal \
        busctl monitor --json=pretty --match 'sender=org.freedesktop.login1,path=/org/freedesktop/login1,interface=org.freedesktop.login1.Manager,member=PrepareForShutdownWithMetadata,type=signal'
    systemd-run --unit inhibit.service --service-type=exec \
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
