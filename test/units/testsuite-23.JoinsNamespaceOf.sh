#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# Test JoinsNamespaceOf= with PrivateTmp=yes

systemd-analyze log-level debug
systemd-analyze log-target journal

# simple case
systemctl start testsuite-23-joins-namespace-of-1.service
systemctl start testsuite-23-joins-namespace-of-2.service
systemctl start testsuite-23-joins-namespace-of-3.service
systemctl stop testsuite-23-joins-namespace-of-1.service

# inverse dependency
systemctl start testsuite-23-joins-namespace-of-4.service
systemctl start testsuite-23-joins-namespace-of-5.service
systemctl stop testsuite-23-joins-namespace-of-4.service

# transitive dependency
systemctl start testsuite-23-joins-namespace-of-6.service
systemctl start testsuite-23-joins-namespace-of-7.service
systemctl start testsuite-23-joins-namespace-of-8.service
systemctl start testsuite-23-joins-namespace-of-9.service
systemctl stop testsuite-23-joins-namespace-of-6.service
systemctl stop testsuite-23-joins-namespace-of-8.service

systemd-analyze log-level info
