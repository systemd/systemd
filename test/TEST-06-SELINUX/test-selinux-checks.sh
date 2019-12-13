#!/bin/bash
set -x
set -e
set -o pipefail

echo 1 >/sys/fs/selinux/enforce
runcon -t systemd_test_start_t systemctl start hola
runcon -t systemd_test_reload_t systemctl reload hola
runcon -t systemd_test_stop_t systemctl stop hola

touch /testok
