#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

echo "Socket" | nc -lkU /tmp/test.sock
