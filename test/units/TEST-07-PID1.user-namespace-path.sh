#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Only reuse the user namespace
systemd-run --unit=oldservice --property=Type=notify --property=NotifyAccess=all --property=PrivateUsers=true bash -c 'systemd-notify --ready; exec sleep 3600'
OLD_PID=$(systemctl show oldservice -p MainPID | awk -F= '{print $2}')

systemd-run --unit=newservice --property=Type=notify --property=NotifyAccess=all --property=UserNamespacePath=/proc/"$OLD_PID"/ns/user --property=PrivateNetwork=true bash -c 'systemd-notify --ready; exec sleep 3600'
NEW_PID=$(systemctl show newservice -p MainPID | awk -F= '{print $2}')

assert_neq "$(readlink /proc/"$OLD_PID"/ns/net)" "$(readlink /proc/"$NEW_PID"/ns/net)"
assert_eq "$(readlink /proc/"$OLD_PID"/ns/user)" "$(readlink /proc/"$NEW_PID"/ns/user)"

systemctl stop oldservice newservice

# Reuse the user and network namespaces
systemd-run --unit=oldservice --property=Type=notify --property=NotifyAccess=all --property=PrivateUsers=true --property=PrivateNetwork=true bash -c 'systemd-notify --ready; exec sleep 3600'
OLD_PID=$(systemctl show oldservice -p MainPID | awk -F= '{print $2}')

systemd-run --unit=newservice --property=Type=notify --property=NotifyAccess=all --property=UserNamespacePath=/proc/"$OLD_PID"/ns/user --property=NetworkNamespacePath=/proc/"$OLD_PID"/ns/net bash -c 'systemd-notify --ready; exec sleep 3600'
NEW_PID=$(systemctl show newservice -p MainPID | awk -F= '{print $2}')

assert_eq "$(readlink /proc/"$OLD_PID"/ns/net)" "$(readlink /proc/"$NEW_PID"/ns/net)"
assert_eq "$(readlink /proc/"$OLD_PID"/ns/user)" "$(readlink /proc/"$NEW_PID"/ns/user)"

systemctl stop oldservice newservice

# Delegate the network namespace
systemd-run --unit=oldservice --property=Type=notify --property=NotifyAccess=all --property=PrivateUsers=true bash -c 'systemd-notify --ready; exec sleep 3600'
OLD_PID=$(systemctl show oldservice -p MainPID | awk -F= '{print $2}')

systemd-run --unit=newservice --property=Type=notify --property=NotifyAccess=all --property=UserNamespacePath=/proc/"$OLD_PID"/ns/user --property=DelegateNamespaces=net --property=PrivateNetwork=true bash -c 'systemd-notify --ready; exec sleep 3600'
NEW_PID=$(systemctl show newservice -p MainPID | awk -F= '{print $2}')

assert_neq "$(readlink /proc/"$OLD_PID"/ns/net)" "$(readlink /proc/"$NEW_PID"/ns/net)"
assert_eq "$(readlink /proc/"$OLD_PID"/ns/user)" "$(readlink /proc/"$NEW_PID"/ns/user)"

systemctl stop oldservice newservice
