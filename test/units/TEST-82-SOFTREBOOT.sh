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

# Because this test tests soft-reboot, we have to get rid of the symlink we put at
# /run/nextroot to allow rebooting into the previous snapshot if the test fails for
# the duration of the test. However, let's make sure we put the symlink back in place
# if the test fails.
if [[ -L /run/nextroot ]]; then
    at_error() {
        mountpoint -q /run/nextroot && umount -R /run/nextroot
        rm -rf /run/nextroot
        ln -sf /snapshot /run/nextroot
    }

    trap at_error ERR
    rm -f /run/nextroot
fi

systemd-analyze log-level debug

export SYSTEMD_LOG_LEVEL=debug

if [ -f /run/TEST-82-SOFTREBOOT.touch3 ]; then
    echo "This is the fourth boot!"
    systemd-notify --status="Fourth Boot"

    test "$(busctl -j get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SoftRebootsCount | jq -r '.data')" -eq 3

    rm /run/TEST-82-SOFTREBOOT.touch3
    mount
    rmdir /original-root /run/nextroot

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 3
    read -r x <&5
    test "$x" = "oinkoink"

    # Check that the surviving services are still around
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-survive.service)" = "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-survive-argv.service)" = "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-nosurvive-sigterm.service)" != "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-nosurvive.service)" != "active"

    [[ ! -e /run/credentials/TEST-82-SOFTREBOOT-nosurvive.service ]]
    assert_eq "$(cat /run/credentials/TEST-82-SOFTREBOOT-survive-argv.service/preserve)" "yay"

    # There may be huge amount of pending messages in sockets. Processing them may cause journal rotation and
    # removal of old archived journal files. If a journal file is removed during journalctl reading it,
    # the command may fail. To mitigate such, sync before reading journals. Workaround for #32834.
    journalctl --sync
    # Check journals
    journalctl -o short-monotonic --no-hostname --grep '(will soft-reboot|KILL|corrupt)'
    assert_eq "$(journalctl -q -o short-monotonic -u systemd-journald.service --grep 'corrupt')" ""

    # All succeeded, exit cleanly now

elif [ -f /run/TEST-82-SOFTREBOOT.touch2 ]; then
    echo "This is the third boot!"
    systemd-notify --status="Third Boot"

    test "$(busctl -j get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SoftRebootsCount | jq -r '.data')" -eq 2

    rm /run/TEST-82-SOFTREBOOT.touch2

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
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-survive.service)" = "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-survive-argv.service)" = "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-nosurvive-sigterm.service)" != "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-nosurvive.service)" != "active"

    # Test that we really are in the new overlayfs root fs
    read -r x </lower
    test "$x" = "miep"
    cmp /etc/os-release /run/systemd/propagate/.os-release-stage/os-release
    grep -q MARKER=1 /etc/os-release

    # Switch back to the original root, away from the overlayfs
    mount --bind /original-root /run/nextroot
    mount

    # Restart the unit that is not supposed to survive
    systemd-run --collect --service-type=exec --unit=TEST-82-SOFTREBOOT-nosurvive.service sleep infinity

    # Now issue the soft reboot. We should be right back soon.
    touch /run/TEST-82-SOFTREBOOT.touch3
    systemctl --no-block soft-reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity

elif [ -f /run/TEST-82-SOFTREBOOT.touch ]; then
    echo "This is the second boot!"
    systemd-notify --status="Second Boot"

    test "$(busctl -j get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SoftRebootsCount | jq -r '.data')" -eq 1

    # Clean up what we created earlier
    rm /run/TEST-82-SOFTREBOOT.touch

    # Check that the fdstore entry still exists
    test "$LISTEN_FDS" -eq 1
    read -r x <&3
    test "$x" = "wuffwuff"

    # Check that we got a PrepareForShutdownWithMetadata signal with the right type
    cat /run/TEST-82-SOFTREBOOT.signal
    test "$(jq -r '.payload.data[1].type.data' </run/TEST-82-SOFTREBOOT.signal)" = "soft-reboot"

    # Check that the system credentials survived the soft reboot.
    test "$(systemd-creds cat --system kernelcmdlinecred)" = "uff"

    # Upload another entry
    T="/dev/shm/fdstore.$RANDOM"
    echo "miaumiau" >"$T"
    systemd-notify --fd=3 --pid=parent 3<"$T"
    rm "$T"

    # Check that the surviving services are still around
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-survive.service)" = "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-survive-argv.service)" = "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-nosurvive-sigterm.service)" != "active"
    test "$(systemctl show -P ActiveState TEST-82-SOFTREBOOT-nosurvive.service)" != "active"

    # This time we test the /run/nextroot/ root switching logic. (We synthesize a new rootfs from the old via overlayfs)
    mkdir -p /run/nextroot /tmp/nextroot-lower /original-root
    mount -t tmpfs tmpfs /tmp/nextroot-lower
    echo miep >/tmp/nextroot-lower/lower

    # Copy os-release away, so that we can manipulate it and check that it is updated in the propagate
    # directory across soft reboots. Try to cover corner cases by truncating it.
    mkdir -p /tmp/nextroot-lower/etc
    grep ID /etc/os-release >/tmp/nextroot-lower/etc/os-release
    echo MARKER=1 >>/tmp/nextroot-lower/etc/os-release
    cmp /etc/os-release /run/systemd/propagate/.os-release-stage/os-release
    (! grep -q MARKER=1 /etc/os-release)

    mount -t overlay nextroot /run/nextroot -o lowerdir=/tmp/nextroot-lower:/,ro

    # Bind our current root into the target so that we later can return to it
    mount --bind / /run/nextroot/original-root

    # Restart the unit that is not supposed to survive
    systemd-run --collect --service-type=exec --unit=TEST-82-SOFTREBOOT-nosurvive.service sleep infinity

    # Now ensure there are no naming clashes and a bunch of transient units all succeed
    for _ in $(seq 1 25); do
        systemd-run --wait true
    done

    # Now issue the soft reboot. We should be right back soon. Given /run/nextroot exists, we should
    # automatically do a softreboot instead of normal reboot.
    touch /run/TEST-82-SOFTREBOOT.touch2
    systemctl --no-block reboot

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity
else
    # This is the first boot
    systemd-notify --status="First Boot"

    test "$(busctl -j get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SoftRebootsCount | jq -r '.data')" -eq 0

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
    systemd-run --collect --service-type=notify -p DefaultDependencies=no -p IgnoreOnIsolate=yes --unit=TEST-82-SOFTREBOOT-nosurvive-sigterm.service "$survive_sigterm"
    systemd-run --collect --service-type=exec -p DefaultDependencies=no -p IgnoreOnIsolate=yes -p SetCredential=gone:hoge --unit=TEST-82-SOFTREBOOT-nosurvive.service sleep infinity

    # Ensure that the unit doesn't get deactivated by dependencies on the source file. Given it's a verity
    # image that is already open, even if the tmpfs with the image goes away, the file will be pinned by the
    # kernel and will keep working.
    cp /usr/share/minimal_0.* /tmp/

    # Configure these transient units to survive the soft reboot - they will not conflict with shutdown.target
    # and it will be ignored on the isolate that happens in the next boot. The first will use argv[0][0] =
    # '@', and the second will use SurviveFinalKillSignal=yes. Both should survive.
    # By writing to stdout, which is connected to the journal, we also ensure logging doesn't break across
    # soft reboots due to journald being temporarily stopped.
    systemd-run --service-type=notify --unit=TEST-82-SOFTREBOOT-survive-argv.service \
        --property SurviveFinalKillSignal=no \
        --property IgnoreOnIsolate=yes \
        --property DefaultDependencies=no \
        --property After=basic.target \
        --property "Conflicts=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
        --property "Before=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
        --property SetCredential=preserve:yay \
         "$survive_argv"
    # shellcheck disable=SC2016
    systemd-run --service-type=exec --unit=TEST-82-SOFTREBOOT-survive.service \
        --property TemporaryFileSystem="/run /tmp /var" \
        --property RootImage=/tmp/minimal_0.raw \
        --property SurviveFinalKillSignal=yes \
        --property IgnoreOnIsolate=yes \
        --property DefaultDependencies=no \
        --property After=basic.target \
        --property "Conflicts=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
        --property "Before=reboot.target kexec.target poweroff.target halt.target emergency.target rescue.target" \
        bash -c 'count=0; while echo "$count"; do count=$[$count +1]; sleep 1; done'

    # Check that we can set up an inhibitor, and that busctl monitor sees the
    # PrepareForShutdownWithMetadata signal and that it says 'soft-reboot'.
    systemd-run --unit busctl.service --service-type=exec --property StandardOutput=file:/run/TEST-82-SOFTREBOOT.signal \
        busctl monitor --json=pretty --match 'sender=org.freedesktop.login1,path=/org/freedesktop/login1,interface=org.freedesktop.login1.Manager,member=PrepareForShutdownWithMetadata,type=signal'
    systemd-run --unit inhibit.service --service-type=exec \
        systemd-inhibit --what=shutdown --who=test --why=test --mode=delay \
            sleep infinity

    # Enqueue a bunch of failing units to try and trigger the transient name clash that happens due to D-Bus
    # being restarted and the "unique" bus IDs not being unique across restarts
    for _ in $(seq 1 25); do
        # Use --wait to ensure we connect to the system bus instead of the private bus (otherwise a UUID is
        # used instead of the bus ID)
        systemd-run --wait false || true
    done

    # Now issue the soft reboot. We should be right back soon.
    touch /run/TEST-82-SOFTREBOOT.touch
    systemctl --no-block --check-inhibitors=yes soft-reboot

    # Ensure the property works too
    type="$(busctl --json=short get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager PreparingForShutdownWithMetadata | jq -r '.data.type.data')"
    test "$type" = "soft-reboot"

    # Now block until the soft-boot killing spree kills us
    exec sleep infinity
fi

systemd-analyze log-level info

touch /testok
systemctl --no-block exit 123
