#!/bin/sh
#  SPDX-License-Identifier: LGPL-2.1-or-later
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[ "$SYSTEM_ENVIRONMENT_LOADED" = 1 ] && return

generate_environ() {
    environment_path="/run/systemd/user-environment-generators /etc/systemd/user-environment-generators /usr/local/lib/systemd/user-environment-generators /usr/lib/systemd/user-environment-generators"

    for file in $(find $environment_path -type f -exec basename {} \; 2>/dev/null|sort -u)
    do
        for dir in $environment_path
            do
            generator="$dir/$file"
            [ -f "$generator" ] && break
        done

        [ "$(readlink "$generator")" != /dev/null ] && [ -s "$generator" ] && [ -x "$generator" ] && "$generator"

    done

    unset environment_path generator
}

set -a
eval "$(generate_environ)"
[ -z "$LANG" ] && [ -r /etc/locale.conf ] && . /etc/locale.conf
SYSTEM_ENVIRONMENT_LOADED=1
set +a

unset -f generate_environ
