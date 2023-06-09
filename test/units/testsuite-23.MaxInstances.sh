#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

systemctl start testsuite-23.MaxInstances@1.service
systemctl start testsuite-23.MaxInstances@2.service
(! systemctl start testsuite-23.MaxInstances@3.service)
systemctl stop testsuite-23.MaxInstances@1.service
systemctl start testsuite-23.MaxInstances@3.service
(! systemctl start testsuite-23.MaxInstances@4.service)

systemctl stop testsuite-23.MaxInstances@*.service

touch /testok
rm /failed
