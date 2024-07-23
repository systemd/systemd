#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for the --purge switch
#
set -eux
set -o pipefail

# TODO: Remove again when Fedora's drops the --destroy-data patch from its spec
# https://src.fedoraproject.org/rpms/systemd/blob/rawhide/f/0001-tmpfiles-make-purge-hard-to-mis-use.patch
DESTROY_DATA=""
if [[ "$(systemd-tmpfiles --help)" =~ --destroy-data ]]; then
    DESTROY_DATA=--destroy-data
fi

export SYSTEMD_LOG_LEVEL=debug

c='
d /tmp/somedir
f /tmp/somedir/somefile - - - - baz
'

systemd-tmpfiles --create - <<<"$c"
test -f /tmp/somedir/somefile
grep -q baz /tmp/somedir/somefile

systemd-tmpfiles --purge --dry-run - <<<"$c"
test -f /tmp/somedir/somefile
grep -q baz /tmp/somedir/somefile

systemd-tmpfiles --purge "$DESTROY_DATA" - <<<"$c"
test ! -f /tmp/somedir/somefile
test ! -d /tmp/somedir/

systemd-tmpfiles --create --purge --dry-run - <<<"$c"
test ! -f /tmp/somedir/somefile
test ! -d /tmp/somedir/

systemd-tmpfiles --create "$DESTROY_DATA" --purge - <<<"$c"
test -f /tmp/somedir/somefile
grep -q baz /tmp/somedir/somefile
