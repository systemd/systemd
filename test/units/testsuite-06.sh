#!/usr/bin/env bash
set -x
set -e
set -o pipefail

echo 1 >/sys/fs/selinux/enforce || {
    echo "Can't make selinux enforcing, skipping test"
    touch /testok
    exit
}

runcon -t systemd_test_start_t systemctl start hola
runcon -t systemd_test_reload_t systemctl reload hola
runcon -t systemd_test_stop_t systemctl stop hola

touch /testok
