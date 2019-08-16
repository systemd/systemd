#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

# Set everything up without DynamicUser=1

systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz touch /var/lib/zzz/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test
! systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test-missing

test -d /var/lib/zzz
! test -L /var/lib/zzz
! test -e /var/lib/private/zzz
test -f /var/lib/zzz/test
! test -f /var/lib/zzz/test-missing

# Convert to DynamicUser=1

systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz test -f /var/lib/zzz/test
! systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz test -f /var/lib/zzz/test-missing

test -L /var/lib/zzz
test -d /var/lib/private/zzz

test -f /var/lib/zzz/test
! test -f /var/lib/zzz/test-missing

# Convert back

systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test
! systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test-missing

test -d /var/lib/zzz
! test -L /var/lib/zzz
! test -e /var/lib/private/zzz
test -f /var/lib/zzz/test
! test -f /var/lib/zzz/test-missing

systemd-analyze log-level info

echo OK > /testok

exit 0
