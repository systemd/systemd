#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
if [[ ! -f "/succeeds-on-restart.ko" ]]
then
    touch "/succeeds-on-restart.ko"
    exit 1
else
    rm "/succeeds-on-restart.ko"
    exit 0
fi
