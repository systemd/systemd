#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

busctl --help
busctl help
busctl --version
busctl
busctl list --no-pager --allow-interactive-authorization=no
busctl list
busctl list --unique --show-machine --full
# Pass the JSON output (-j) through jq to check if it's valid
busctl list --acquired --activatable --no-legend -j | jq
busctl status
busctl status --machine=.host --augment-creds=no
busctl status --user --machine=testuser@.host
busctl status org.freedesktop.systemd1
# Ignore the exit code here, since this runs during machine bootup, so busctl
# might attempt to introspect a job that already finished and fail, i.e.:
# Failed to introspect object /org/freedesktop/systemd1/job/335 of service org.freedesktop.systemd1: Unknown object '/org/freedesktop/systemd1/job/335'.
busctl tree || :
busctl tree org.freedesktop.login1
busctl tree --list org.freedesktop.login1
busctl introspect org.freedesktop.systemd1 /org/freedesktop/systemd1
busctl introspect --watch-bind=yes --xml-interface org.freedesktop.systemd1 /org/freedesktop/LogControl1
busctl introspect org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager

busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            GetDefaultTarget
# Pass both JSON outputs through jq to check if the response JSON is valid
busctl call --json=pretty \
            org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            ListUnitsByNames as 2 "systemd-journald.service" "systemd-logind.service" | jq
busctl call --json=short \
            org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            ListUnitsByNames as 2 "systemd-journald.service" "systemd-logind.service" | jq
# Get all properties on the org.freedesktop.systemd1.Manager interface and dump
# them as JSON to exercise the internal JSON transformations
busctl call -j \
            org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.DBus.Properties \
            GetAll s "org.freedesktop.systemd1.Manager" | jq -c
busctl call --verbose --timeout=60 --expect-reply=yes \
            org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            ListUnitsByPatterns asas 1 "active" 2 "systemd-*.socket" "*.mount"
# show information passed fd
busctl call --json=pretty \
            org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            DumpByFileDescriptor | jq

busctl emit /org/freedesktop/login1 org.freedesktop.login1.Manager \
            PrepareForSleep b false
busctl emit --auto-start=no --destination=systemd-logind.service \
            /org/freedesktop/login1 org.freedesktop.login1.Manager \
            PrepareForShutdown b false

systemd-run --quiet --service-type=notify --unit=test-busctl-wait --pty \
	-p ExecStartPost="busctl emit /test org.freedesktop.fake1 TestSignal s success" \
	busctl --timeout=3 wait /test org.freedesktop.fake1 TestSignal | grep -qF 's "success"'

busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                    Version
busctl get-property --verbose \
                    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                    LogLevel LogTarget SystemState Version
# Pass both JSON outputs through jq to check if the response JSON is valid
busctl get-property --json=pretty \
                    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                    LogLevel LogTarget SystemState Version | jq
busctl get-property --json=short \
                    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                    LogLevel LogTarget SystemState Version | jq

# Set a property and check if it was indeed set
busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                    KExecWatchdogUSec t 666
busctl get-property -j \
                    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                    KExecWatchdogUSec | jq -e '.data == 666'

(! busctl status org.freedesktop.systemd2)
(! busctl tree org.freedesktop.systemd2)
(! busctl introspect org.freedesktop.systemd1)
(! busctl introspect org.freedesktop.systemd1 /org/freedesktop/systemd2)
(! busctl introspect org.freedesktop.systemd2 /org/freedesktop/systemd1)

# Invalid method
(! busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
               ThisMethodDoesntExist)
# Invalid signature
(! busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
               ListUnitsByNames ab 1 false)
# Invalid arguments
(! busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
               GetUnitByPID u "hello")
(! busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
               -- ListUnitsByNames as -1 "systemd-journald.service")
# Not enough arguments
(! busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
               ListUnitsByNames as 99 "systemd-journald.service")

(! busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                       NonexistentProperty)
(! busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                       Version NonexistentProperty Version)

# Invalid property
(! busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                       NonexistentProperty t 666)
# Invalid signature
(! busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                       KExecWatchdogUSec s 666)
# Invalid argument
(! busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                       KExecWatchdogUSec t "foo")

busctl --quiet --timeout=1 --limit-messages=1 --match "interface=org.freedesktop.systemd1.Manager" monitor

START_USEC=$(date +%s%6N)
busctl --quiet --timeout=500ms --match "interface=io.dontexist.NeverGonnaHappen" monitor
END_USEC=$(date +%s%6N)
USEC=$((END_USEC-START_USEC))
# Validate that the above was delayed for at least 500ms, but at most 30s (some leeway for slow CIs)
test "$USEC" -gt 500000
test "$USEC" -lt 30000000
