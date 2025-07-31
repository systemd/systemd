#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run -v --wait echo wampfl | grep wampfl
systemd-run -v --service-type=notify bash -c 'echo brumfl ; systemd-notify --ready ; echo krass' | grep brumfl
