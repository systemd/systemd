#!/bin/sh -eu
# SPDX-License-Identifier: CC0-1.0

test -e /etc/os-release && os_release='/etc/os-release' || os_release='/usr/lib/os-release'
. "${os_release}"

echo "Running on ${PRETTY_NAME:-Linux}"

if [ "${ID:-linux}" = "debian" ] || [ "${ID_LIKE#*debian*}" != "${ID_LIKE}" ]; then
    echo "Looks like Debian!"
fi
