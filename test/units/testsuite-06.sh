#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

runcon -t systemd_test_start_t systemctl start hola
runcon -t systemd_test_reload_t systemctl reload hola
runcon -t systemd_test_stop_t systemctl stop hola

touch /testok
