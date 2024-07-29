#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Simple wrapper to check both escaping and unescaping of given strings
# Arguments:
#   $1 - expected unescaped string
#   $2 - expected escaped string
#   $3 - optional arguments for systemd-escape
check_escape() {
    unescaped="${1?}"
    escaped="${2?}"
    shift 2

    assert_eq "$(systemd-escape "$@" -- "$unescaped")" "$escaped"
    assert_eq "$(systemd-escape "$@" --unescape -- "$escaped")" "$unescaped"
}

systemd-escape --help
systemd-escape --version

check_escape '' ''
check_escape 'hello' 'hello'
check_escape 'hello-world' 'hello\x2dworld'
check_escape '-+ěščřž---🤔' '\x2d\x2b\xc4\x9b\xc5\xa1\xc4\x8d\xc5\x99\xc5\xbe\x2d\x2d\x2d\xf0\x9f\xa4\x94'
check_escape '/this/is/a/path/a b c' '-this-is-a-path-a\x20b\x20c'

# Multiple strings to escape/unescape
assert_eq "$(systemd-escape 'hello-world' '/dev/loop1' 'template@🐍')" \
          'hello\x2dworld -dev-loop1 template\x40\xf0\x9f\x90\x8d'
assert_eq "$(systemd-escape --unescape -- 'hello\x2dworld' '-dev-loop1' 'template\x40\xf0\x9f\x90\x8d')" \
          'hello-world /dev/loop1 template@🐍'

# --suffix= is not compatible with --unescape
assert_eq "$(systemd-escape --suffix=mount -- '-+ěščřž---🤔')" \
          '\x2d\x2b\xc4\x9b\xc5\xa1\xc4\x8d\xc5\x99\xc5\xbe\x2d\x2d\x2d\xf0\x9f\xa4\x94.mount'
assert_eq "$(systemd-escape --suffix=timer 'this has spaces')" \
          'this\x20has\x20spaces.timer'
assert_eq "$(systemd-escape --suffix=service 'trailing-spaces  ')" \
          'trailing\x2dspaces\x20\x20.service'
assert_eq "$(systemd-escape --suffix=automount '   leading-spaces')" \
          '\x20\x20\x20leading\x2dspaces.automount'

# --template=
check_escape 'hello' 'hello@hello.service' --template=hello@.service
check_escape '  what - is _ love? 🤔 ¯\_(ツ)_/¯' \
             'hello@\x20\x20what\x20\x2d\x20is\x20_\x20love\x3f\x20\xf0\x9f\xa4\x94\x20\xc2\xaf\x5c_\x28\xe3\x83\x84\x29_-\xc2\xaf.service' \
             --template=hello@.service
check_escape '/this/is/where/my/stuff/is/ with spaces though ' \
             'mount-my-stuff@-this-is-where-my-stuff-is-\x20with\x20spaces\x20though\x20.service' \
             --template=mount-my-stuff@.service
check_escape '/this/is/where/my/stuff/is/ with spaces though ' \
             'mount-my-stuff@this-is-where-my-stuff-is-\x20with\x20spaces\x20though\x20.service' \
             --template=mount-my-stuff@.service --path

# --instance (must be used with --unescape)
assert_eq "$(systemd-escape --unescape --instance 'hello@\x20\x20what\x20\x2d\x20is\x20_\x20love\x3f\x20\xf0\x9f\xa4\x94\x20\xc2\xaf\x5c_\x28\xe3\x83\x84\x29_-\xc2\xaf.service')" \
          '  what - is _ love? 🤔 ¯\_(ツ)_/¯'
assert_eq "$(systemd-escape --unescape --instance 'mount-my-stuff@-this-is-where-my-stuff-is-\x20with\x20spaces\x20though\x20.service')" \
          '/this/is/where/my/stuff/is/ with spaces though '
assert_eq "$(systemd-escape --unescape --instance --path 'mount-my-stuff@this-is-where-my-stuff-is-\x20with\x20spaces\x20though\x20.service')" \
          '/this/is/where/my/stuff/is/ with spaces though '

# --path, reversible cases
check_escape / '-' --path
check_escape '/hello/world' 'hello-world' --path
check_escape '/mnt/smb/おにぎり' \
             'mnt-smb-\xe3\x81\x8a\xe3\x81\xab\xe3\x81\x8e\xe3\x82\x8a' \
             --path

# --path, non-reversible cases
assert_eq "$(systemd-escape --path ///////////////)" '-'
assert_eq "$(systemd-escape --path /..)" '-'
assert_eq "$(systemd-escape --path /../.././../.././)" '-'
assert_eq "$(systemd-escape --path /../.././../.././foo)" 'foo'

# --mangle
assert_eq "$(systemd-escape --mangle 'hello-world')" 'hello-world.service'
assert_eq "$(systemd-escape --mangle '/mount/this')" 'mount-this.mount'
assert_eq "$(systemd-escape --mangle 'my-service@ 🐱 ')" 'my-service@\x20\xf0\x9f\x90\xb1\x20.service'
assert_eq "$(systemd-escape --mangle '/dev/disk/by-emoji/🍎')" 'dev-disk-by\x2demoji-\xf0\x9f\x8d\x8e.device'
assert_eq "$(systemd-escape --mangle 'daily-existential-crisis .timer')" 'daily-existential-crisis\x20.timer'
assert_eq "$(systemd-escape --mangle 'trailing-whitespace.mount ')" 'trailing-whitespace.mount\x20.service'

(! systemd-escape)
(! systemd-escape --suffix='' hello)
(! systemd-escape --suffix=invalid hello)
(! systemd-escape --suffix=mount --template=hello@.service hello)
(! systemd-escape --suffix=mount --mangle)
(! systemd-escape --template='')
(! systemd-escape --template=@)
(! systemd-escape --template='hello@.service' '')
(! systemd-escape --unescape --template='hello@.service' '@hello.service')
(! systemd-escape --unescape --template='hello@.service' 'hello@.service')
(! systemd-escape --mangle --template=hello@.service hello)
(! systemd-escape --instance 'hello@hello.service')
(! systemd-escape --instance --template=hello@.service 'hello@hello.service')
(! systemd-escape --unescape --instance --path 'mount-my-stuff@-this-is-where-my-stuff-is-\x20with\x20spaces\x20though\x20.service')
(! systemd-escape --path '/../hello/..')
(! systemd-escape --path '.')
(! systemd-escape --path '..')
(! systemd-escape --path "$(set +x; printf '%0.sa' {0..256})")
(! systemd-escape --unescape --path '')
(! systemd-escape --mangle '')
