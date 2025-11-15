#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# When sanitizers are used, export LD_PRELOAD with the sanitizers path,
# lsns doesn't work otherwise.
if [ -f /usr/lib/systemd/systemd-asan-env ]; then
    # shellcheck source=/dev/null
    . /usr/lib/systemd/systemd-asan-env
    export LD_PRELOAD
    export ASAN_OPTIONS
fi

# Only reuse the user namespace
systemd-run --unit=oldservice --property=Type=exec --property=PrivateUsers=true sleep 3600
OLD_PID=$(systemctl show oldservice -p MainPID | awk -F= '{print $2}')

systemd-run --unit=newservice --property=Type=exec --property=UserNamespacePath=/proc/"$OLD_PID"/ns/user --property=PrivateNetwork=true sleep 3600
NEW_PID=$(systemctl show newservice -p MainPID | awk -F= '{print $2}')

assert_neq "$(lsns -p "$OLD_PID" -o NS -t net -n)" "$(lsns -p "$NEW_PID" -o NS -t net -n)"
assert_eq "$(lsns -p "$OLD_PID" -o NS -t user -n)" "$(lsns -p "$NEW_PID" -o NS -t user -n)"

systemctl stop oldservice newservice

# Reuse the user and network namespaces
systemd-run --unit=oldservice --property=Type=exec --property=PrivateUsers=true --property=PrivateNetwork=true sleep 3600
OLD_PID=$(systemctl show oldservice -p MainPID | awk -F= '{print $2}')

systemd-run --unit=newservice --property=Type=exec --property=UserNamespacePath=/proc/"$OLD_PID"/ns/user --property=NetworkNamespacePath=/proc/"$OLD_PID"/ns/net sleep 3600
NEW_PID=$(systemctl show newservice -p MainPID | awk -F= '{print $2}')

assert_eq "$(lsns -p "$OLD_PID" -o NS -t net -n)" "$(lsns -p "$NEW_PID" -o NS -t net -n)"
assert_eq "$(lsns -p "$OLD_PID" -o NS -t user -n)" "$(lsns -p "$NEW_PID" -o NS -t user -n)"

systemctl stop oldservice newservice

# Delegate the network namespace
systemd-run --unit=oldservice --property=Type=exec --property=PrivateUsers=true sleep 3600
OLD_PID=$(systemctl show oldservice -p MainPID | awk -F= '{print $2}')

systemd-run --unit=newservice --property=Type=exec --property=UserNamespacePath=/proc/"$OLD_PID"/ns/user --property=DelegateNamespaces=net --property=PrivateNetwork=true sleep 3600
NEW_PID=$(systemctl show newservice -p MainPID | awk -F= '{print $2}')

assert_neq "$(lsns -p "$OLD_PID" -o NS -t net -n)" "$(lsns -p "$NEW_PID" -o NS -t net -n)"
assert_eq "$(lsns -p "$OLD_PID" -o NS -t user -n)" "$(lsns -p "$NEW_PID" -o NS -t user -n)"

systemctl stop oldservice newservice
