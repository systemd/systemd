#!/bin/bash -eux
# SPDX-License-Identifier: LGPL-2.1-or-later

systemctl --failed --no-legend | tee /failed-services

# Exit with non-zero EC if the /failed-services file is not empty (we have -e set)
[[ ! -s /failed-services ]]

: >/testok
