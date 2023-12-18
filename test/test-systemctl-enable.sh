#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

# Silence warning from running_in_chroot_or_offline()
export SYSTEMD_IGNORE_CHROOT=1

systemctl=${1:-systemctl}
systemd_id128=${2:-systemd-id128}

unset root
cleanup() {
    [ -n "$root" ] && rm -rf "$root"
}
trap cleanup exit
root=$(mktemp -d --tmpdir systemctl-test.XXXXXX)

islink() {
    test -h "$1" || return 1
    test "$(readlink "$1")" = "$2" || return 2
}

: '-------enable nonexistent--------------------------------------'
( ! "$systemctl" --root="$root" enable test1.service )

: '-------basic enablement----------------------------------------'
mkdir -p "$root/etc/systemd/system"
cat >"$root/etc/systemd/system/test1.service" <<EOF
[Install]
WantedBy=default.target
RequiredBy=special.target
EOF

"$systemctl" --root="$root" enable test1.service
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test -h "$root/etc/systemd/system/special.target.requires/test1.service"

"$systemctl" --root="$root" reenable test1.service
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test -h "$root/etc/systemd/system/special.target.requires/test1.service"

"$systemctl" --root="$root" disable test1.service
test ! -h "$root/etc/systemd/system/default.target.wants/test1.service"
test ! -h "$root/etc/systemd/system/special.target.requires/test1.service"

: '-------enable when link already exists-------------------------'
# We don't read the symlink target, so it's OK for the symlink to point
# to something else. We should just silently accept this.

mkdir -p "$root/etc/systemd/system/default.target.wants"
mkdir -p "$root/etc/systemd/system/special.target.requires"
ln -s /usr/lib/systemd/system/test1.service "$root/etc/systemd/system/default.target.wants/test1.service"
ln -s /usr/lib/systemd/system/test1.service "$root/etc/systemd/system/special.target.requires/test1.service"

"$systemctl" --root="$root" enable test1.service
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test -h "$root/etc/systemd/system/special.target.requires/test1.service"

"$systemctl" --root="$root" reenable test1.service
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test -h "$root/etc/systemd/system/special.target.requires/test1.service"

"$systemctl" --root="$root" disable test1.service
test ! -h "$root/etc/systemd/system/default.target.wants/test1.service"
test ! -h "$root/etc/systemd/system/special.target.requires/test1.service"

: '-------suffix guessing-----------------------------------------'
"$systemctl" --root="$root" enable test1
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test -h "$root/etc/systemd/system/special.target.requires/test1.service"

"$systemctl" --root="$root" reenable test1
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test -h "$root/etc/systemd/system/special.target.requires/test1.service"

"$systemctl" --root="$root" disable test1
test ! -e "$root/etc/systemd/system/default.target.wants/test1.service"
test ! -e "$root/etc/systemd/system/special.target.requires/test1.service"

: '-------aliases-------------------------------------------------'
cat >>"$root/etc/systemd/system/test1.service" <<EOF
Alias=test1-goodalias.service
Alias=test1@badalias.service
Alias=test1-badalias.target
Alias=test1-badalias.socket
# we have a series of good, bad, and then good again
Alias=test1-goodalias2.service
EOF

( ! "$systemctl" --root="$root" enable test1 )
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test -h "$root/etc/systemd/system/special.target.requires/test1.service"
test ! -e "$root/etc/systemd/system/test1-goodalias.service"
test -h "$root/etc/systemd/system/test1-goodalias.service"
test ! -e "$root/etc/systemd/system/test1@badalias.service"
test ! -e "$root/etc/systemd/system/test1-badalias.target"
test ! -e "$root/etc/systemd/system/test1-badalias.socket"
test -h "$root/etc/systemd/system/test1-goodalias2.service"

: '-------aliases in reenable-------------------------------------'
( ! "$systemctl" --root="$root" reenable test1 )
test -h "$root/etc/systemd/system/default.target.wants/test1.service"
test ! -e "$root/etc/systemd/system/test1-goodalias.service"
test -h "$root/etc/systemd/system/test1-goodalias.service"

test ! -e "$root/etc/systemd/system/test1@badalias.service"
test ! -e "$root/etc/systemd/system/test1-badalias.target"
test ! -e "$root/etc/systemd/system/test1-badalias.socket"

"$systemctl" --root="$root" disable test1
test ! -e "$root/etc/systemd/system/default.target.wants/test1.service"
test ! -e "$root/etc/systemd/system/special.target.requires/test1.service"
test ! -e "$root/etc/systemd/system/test1-goodalias.service"

: '-------aliases when link already exists------------------------'
cat >"$root/etc/systemd/system/test1a.service" <<EOF
[Install]
Alias=test1a-alias.service
EOF

ln -s /usr/lib/systemd/system/test1a.service "$root/etc/systemd/system/test1a-alias.service"

"$systemctl" --root="$root" enable test1a.service
test -h "$root/etc/systemd/system/test1a-alias.service"

"$systemctl" --root="$root" disable test1a.service
test ! -h "$root/etc/systemd/system/test1a-alias.service"

: '-------also units----------------------------------------------'
cat >"$root/etc/systemd/system/test2.socket" <<EOF
[Install]
WantedBy=sockets.target
Also=test2.service
EOF

cat >"$root/etc/systemd/system/test2.service" <<EOF
[Install]
WantedBy=default.target
Also=test2.socket
EOF

"$systemctl" --root="$root" reenable test2.service
test -h "$root/etc/systemd/system/default.target.wants/test2.service"
test -h "$root/etc/systemd/system/sockets.target.wants/test2.socket"

"$systemctl" --root="$root" reenable test2.socket
test -h "$root/etc/systemd/system/default.target.wants/test2.service"
test -h "$root/etc/systemd/system/sockets.target.wants/test2.socket"

"$systemctl" --root="$root" disable test2.socket
test ! -e "$root/etc/systemd/system/default.target.wants/test2.service"
test ! -e "$root/etc/systemd/system/sockets.target.wants/test2.socket"


: '-------link----------------------------------------------------'
# File doesn't exist yet
test ! -e "$root/link1.path"
( ! "$systemctl" --root="$root" link '/link1.path' )
test ! -e "$root/etc/systemd/system/link1.path"

cat >"$root/link1.path" <<EOF
[Install]
WantedBy=paths.target
EOF

"$systemctl" --root="$root" link '/link1.path'
islink "$root/etc/systemd/system/link1.path" "/link1.path"

: '-------link already linked same path---------------------------'
SYSTEMD_LOG_LEVEL=debug "$systemctl" --root="$root" link '/link1.path'  # this passes
islink "$root/etc/systemd/system/link1.path" "/link1.path"

: '-------link already linked different path----------------------'
mkdir "$root/subdir"
cp "$root/link1.path" "$root/subdir/"
( ! "$systemctl" --root="$root" link '/subdir/link1.path' )
islink "$root/etc/systemd/system/link1.path" "/link1.path"

: '-------link bad suffix-----------------------------------------'
cp "$root/link1.path" "$root/subdir/link1.suffix"
( ! "$systemctl" --root="$root" link '/subdir/link1.suffix' )
test ! -e "$root/etc/systemd/system/link1.suffix"

: '-------unlink by unit name-------------------------------------'
"$systemctl" --root="$root" disable 'link1.path'
test ! -e "$root/etc/systemd/system/link1.path"

: '-------unlink by path------------------------------------------'
"$systemctl" --root="$root" link '/link1.path'
test -h "$root/etc/systemd/system/link1.path"
"$systemctl" --root="$root" disable '/link1.path'
test ! -e "$root/etc/systemd/system/link1.path"

: '-------unlink by wrong path------------------------------------'
"$systemctl" --root="$root" link '/link1.path'
test -h "$root/etc/systemd/system/link1.path"
"$systemctl" --root="$root" disable '/subdir/link1.path'  # we only care about the name
test ! -e "$root/etc/systemd/system/link1.path"


: '-------link and enable-----------------------------------------'
"$systemctl" --root="$root" enable '/link1.path'
islink "$root/etc/systemd/system/link1.path" "/link1.path"
islink "$root/etc/systemd/system/paths.target.wants/link1.path" "/link1.path"

: '-------enable already linked same path-------------------------'
"$systemctl" --root="$root" enable '/link1.path'
islink "$root/etc/systemd/system/link1.path" "/link1.path"
islink "$root/etc/systemd/system/paths.target.wants/link1.path" "/link1.path"

: '-------enable already linked different path--------------------'
( ! "$systemctl" --root="$root" enable '/subdir/link1.path' )
islink "$root/etc/systemd/system/link1.path" "/link1.path"
islink "$root/etc/systemd/system/paths.target.wants/link1.path" "/link1.path"

: '-------enable bad suffix---------------------------------------'
cp "$root/link1.path" "$root/subdir/link1.suffix"
( ! "$systemctl" --root="$root" enable '/subdir/link1.suffix' )
test ! -e "$root/etc/systemd/system/link1.suffix"
test ! -e "$root/etc/systemd/system/paths.target.wants/link1.suffix"

: '-------disable by unit name------------------------------------'
"$systemctl" --root="$root" disable 'link1.path'
test ! -e "$root/etc/systemd/system/link1.path"
test ! -e "$root/etc/systemd/system/paths.target.wants/link1.path"

: '-------disable by path-----------------------------------------'
"$systemctl" --root="$root" enable '/link1.path'
test -h "$root/etc/systemd/system/link1.path"
test -h "$root/etc/systemd/system/paths.target.wants/link1.path"
"$systemctl" --root="$root" disable '/link1.path'
test ! -e "$root/etc/systemd/system/link1.path"
test ! -e "$root/etc/systemd/system/paths.target.wants/link1.path"


: '-------link and enable-----------------------------------------'
"$systemctl" --root="$root" link '/link1.path'
islink "$root/etc/systemd/system/link1.path" "/link1.path"
test ! -h "$root/etc/systemd/system/paths.target.wants/link1.path"

"$systemctl" --root="$root" enable 'link1.path'
islink "$root/etc/systemd/system/link1.path" "/link1.path"
islink "$root/etc/systemd/system/paths.target.wants/link1.path" "/link1.path"

"$systemctl" --root="$root" reenable 'link1.path'
islink "$root/etc/systemd/system/link1.path" "/link1.path"
islink "$root/etc/systemd/system/paths.target.wants/link1.path" "/link1.path"

: '-------link instance and enable--------------------------------'
cat >"$root/link-instance@.service" <<EOF
[Service]
ExecStart=true
[Install]
WantedBy=services.target
EOF

"$systemctl" --root="$root" link '/link-instance@.service'
islink "$root/etc/systemd/system/link-instance@.service" "/link-instance@.service"

"$systemctl" --root="$root" enable 'link-instance@first.service'
islink "$root/etc/systemd/system/link-instance@first.service" "/link-instance@.service"
islink "$root/etc/systemd/system/services.target.wants/link-instance@first.service" "/link-instance@.service"

SYSTEMD_LOG_LEVEL=debug "$systemctl" --root="$root" reenable 'link-instance@first.service'
islink "$root/etc/systemd/system/link-instance@first.service" "/link-instance@.service"
islink "$root/etc/systemd/system/services.target.wants/link-instance@first.service" "/link-instance@.service"

"$systemctl" --root="$root" disable 'link-instance@first.service'
test ! -h "$root/etc/systemd/system/link-instance@first.service"
test ! -h "$root/etc/systemd/system/services.target.wants/link-instance@first.service"

: '-------manual link---------------------------------------------'
cat >"$root/link3.suffix" <<EOF
[Install]
WantedBy=services.target
EOF

# We wouldn't create such a link ourselves, but it should accept it when present.
ln -s "/link3.suffix" "$root/etc/systemd/system/link3.service"

SYSTEMD_LOG_LEVEL=debug SYSTEMD_LOG_LOCATION=1 "$systemctl" --root="$root" enable 'link3.service'
islink "$root/etc/systemd/system/link3.service" "/link3.suffix"
islink "$root/etc/systemd/system/services.target.wants/link3.service" "/link3.suffix"

SYSTEMD_LOG_LEVEL=debug SYSTEMD_LOG_LOCATION=1 "$systemctl" --root="$root" disable 'link3.service'
test ! -h "$root/etc/systemd/system/link3.service"
test ! -h "$root/etc/systemd/system/services.target.wants/link3.service"

: '-------enable on masked----------------------------------------'
ln -s "/dev/null" "$root/etc/systemd/system/masked.service"
( ! "$systemctl" --root="$root" enable 'masked.service' )
( ! "$systemctl" --root="$root" enable '/etc/systemd/system/masked.service' )

: '-------enable on masked alias----------------------------------'
test -h "$root/etc/systemd/system/masked.service"
ln -s "masked.service" "$root/etc/systemd/system/masked-alias.service"
( ! "$systemctl" --root="$root" enable 'masked-alias.service' )
( ! "$systemctl" --root="$root" enable '/etc/systemd/system/masked-alias.service' )

: '-------issue 22000: link in subdirectory-----------------------'
mkdir -p "$root/etc/systemd/system/myown.d"
cat >"$root/etc/systemd/system/link5-also.service" <<EOF
[Install]
WantedBy=services.target
Also=link5.service
EOF
cat >"$root/etc/systemd/system/myown.d/link5.service" <<EOF
[Install]
WantedBy=services.target
Also=link5-also.service
EOF

( ! "$systemctl" --root="$root" enable 'link5.service' )
test ! -h "$root/etc/systemd/system/services.target.wants/link5.service"
test ! -h "$root/etc/systemd/system/services.target.wants/link5-also.service"

"$systemctl" --root="$root" enable 'link5-also.service'
test ! -h "$root/etc/systemd/system/services.target.wants/link5.service"
islink "$root/etc/systemd/system/services.target.wants/link5-also.service" "/etc/systemd/system/link5-also.service"

: '-------template enablement-------------------------------------'
cat >"$root/etc/systemd/system/templ1@.service" <<EOF
[Install]
WantedBy=services.target
EOF

# No instance here — this can't succeed.
( ! "$systemctl" --root="$root" enable 'templ1@.service' )
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"

"$systemctl" --root="$root" enable 'templ1@one.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@one.service" "/etc/systemd/system/templ1@.service"

"$systemctl" --root="$root" enable 'templ1@two.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@one.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@two.service" "/etc/systemd/system/templ1@.service"

"$systemctl" --root="$root" reenable 'templ1@two.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@one.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@two.service" "/etc/systemd/system/templ1@.service"

"$systemctl" --root="$root" disable 'templ1@one.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@one.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@two.service" "/etc/systemd/system/templ1@.service"

"$systemctl" --root="$root" disable 'templ1@two.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@one.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@two.service"

: '-------template enablement w/ default instance-----------------'
cat >"$root/etc/systemd/system/templ1@.service" <<EOF
[Install]
# check enablement with
WantedBy=services.target services.target
RequiredBy=other@templ1.target other@%p.target
DefaultInstance=333
EOF

"$systemctl" --root="$root" enable 'templ1@.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@333.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@333.service" "/etc/systemd/system/templ1@.service"

"$systemctl" --root="$root" enable 'templ1@one.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@333.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@333.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@one.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@one.service" "/etc/systemd/system/templ1@.service"

"$systemctl" --root="$root" enable 'templ1@two.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@333.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@333.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@one.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@one.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@two.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@two.service" "/etc/systemd/system/templ1@.service"

"$systemctl" --root="$root" disable 'templ1@one.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@333.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@333.service" "/etc/systemd/system/templ1@.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@one.service"
test ! -h "$root/etc/systemd/system/other@templ1.target.requires/templ1@one.service"
islink "$root/etc/systemd/system/services.target.wants/templ1@two.service" "/etc/systemd/system/templ1@.service"
islink "$root/etc/systemd/system/other@templ1.target.requires/templ1@two.service" "/etc/systemd/system/templ1@.service"

# disable remaining links here
"$systemctl" --root="$root" disable 'templ1@.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@333.service"
test ! -h "$root/etc/systemd/system/other@templ1.target.requires/templ1@333.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@one.service"
test ! -h "$root/etc/systemd/system/other@templ1.target.requires/templ1@one.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@two.service"
test ! -h "$root/etc/systemd/system/other@templ1.target.requires/templ1@two.service"

: '-------removal of relative enablement symlinks-----------------'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@.service"
ln -s '../templ1@one.service' "$root/etc/systemd/system/services.target.wants/templ1@one.service"
ln -s 'templ1@two.service' "$root/etc/systemd/system/services.target.wants/templ1@two.service"
ln -s '../templ1@.service' "$root/etc/systemd/system/services.target.wants/templ1@three.service"
ln -s 'templ1@.service' "$root/etc/systemd/system/services.target.wants/templ1@four.service"
ln -s '/usr/lib/systemd/system/templ1@.service' "$root/etc/systemd/system/services.target.wants/templ1@five.service"
ln -s '/etc/systemd/system/templ1@.service' "$root/etc/systemd/system/services.target.wants/templ1@six.service"
ln -s '/run/system/templ1@.service' "$root/etc/systemd/system/services.target.wants/templ1@seven.service"

# this should remove all links
"$systemctl" --root="$root" disable 'templ1@.service'
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@one.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@two.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@three.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@four.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@five.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@six.service"
test ! -h "$root/etc/systemd/system/services.target.wants/templ1@seven.service"

: '-------template enablement for another template----------------'
cat >"$root/etc/systemd/system/templ2@.service" <<EOF
[Install]
RequiredBy=another-template@.target
EOF

"$systemctl" --root="$root" enable 'templ2@.service'
islink "$root/etc/systemd/system/another-template@.target.requires/templ2@.service" "/etc/systemd/system/templ2@.service"

"$systemctl" --root="$root" enable 'templ2@two.service'
islink "$root/etc/systemd/system/another-template@.target.requires/templ2@.service" "/etc/systemd/system/templ2@.service"
islink "$root/etc/systemd/system/another-template@.target.requires/templ2@two.service" "/etc/systemd/system/templ2@.service"

"$systemctl" --root="$root" disable 'templ2@other.service'
islink "$root/etc/systemd/system/another-template@.target.requires/templ2@.service" "/etc/systemd/system/templ2@.service"
islink "$root/etc/systemd/system/another-template@.target.requires/templ2@two.service" "/etc/systemd/system/templ2@.service"

"$systemctl" --root="$root" disable 'templ2@two.service'
islink "$root/etc/systemd/system/another-template@.target.requires/templ2@.service" "/etc/systemd/system/templ2@.service"
test ! -h "$root/etc/systemd/system/another-template@.target.requires/templ2@two.service"

"$systemctl" --root="$root" disable 'templ2@.service'
test ! -h "$root/etc/systemd/system/another-template@.target.requires/templ2@.service"
test ! -h "$root/etc/systemd/system/another-template@.target.requires/templ2@two.service"

: '-------aliases w/ and w/o instance-----------------------------'
test ! -e "$root/etc/systemd/system/link4.service"
cat >"$root/etc/systemd/system/link4.service" <<EOF
[Install]
Alias=link4.service
Alias=link4@.service
Alias=link4@inst.service
Alias=link4alias.service
Alias=link4alias2.service
EOF

( ! "$systemctl" --root="$root" enable 'link4.service' )
test ! -h "$root/etc/systemd/system/link4.service"  # this is our file
test ! -h "$root/etc/systemd/system/link4@.service"
test ! -h "$root/etc/systemd/system/link4@inst.service"
islink "$root/etc/systemd/system/link4alias.service" "/etc/systemd/system/link4.service"
islink "$root/etc/systemd/system/link4alias2.service" "/etc/systemd/system/link4.service"

"$systemctl" --root="$root" disable 'link4.service'
test ! -h "$root/etc/systemd/system/link4.service"
test ! -h "$root/etc/systemd/system/link4@.service"
test ! -h "$root/etc/systemd/system/link4@inst.service"
test ! -h "$root/etc/systemd/system/link4alias.service"
test ! -h "$root/etc/systemd/system/link4alias2.service"

: '-------systemctl enable on path to unit file-------------------'
cat >"$root/etc/systemd/system/link4.service" <<EOF
[Install]
Alias=link4alias.service
Alias=link4alias2.service
EOF

# Apparently this works. I'm not sure what to think.
"$systemctl" --root="$root" enable '/etc/systemd/system/link4.service'
test ! -h "$root/etc/systemd/system/link4.service"  # this is our file
islink "$root/etc/systemd/system/link4alias.service" "/etc/systemd/system/link4.service"
islink "$root/etc/systemd/system/link4alias2.service" "/etc/systemd/system/link4.service"

"$systemctl" --root="$root" disable '/etc/systemd/system/link4.service'
test ! -h "$root/etc/systemd/system/link4.service"
test ! -h "$root/etc/systemd/system/link4alias.service"
test ! -h "$root/etc/systemd/system/link4alias2.service"

: '-------issue 661: enable on unit file--------------------------'
test ! -e "$root/etc/systemd/system/link5.service"
cat >"$root/etc/systemd/system/link5.service" <<EOF
[Install]
Alias=link5.service
Alias=link5alias.service
Alias=link5alias2.service
EOF

"$systemctl" --root="$root" enable 'link5.service'
test ! -h "$root/etc/systemd/system/link5.service"  # this is our file
islink "$root/etc/systemd/system/link5alias.service" "/etc/systemd/system/link5.service"
islink "$root/etc/systemd/system/link5alias2.service" "/etc/systemd/system/link5.service"

"$systemctl" --root="$root" disable 'link5.service'
test ! -h "$root/etc/systemd/system/link5alias.service"
test ! -h "$root/etc/systemd/system/link5alias2.service"

: '-------issue 661: link and enable on unit file-----------------'
test ! -e "$root/etc/systemd/system/link5copy.service"
cat >"$root/link5copy.service" <<EOF
[Install]
Alias=link5copy.service
Alias=link5alias.service
Alias=link5alias2.service
EOF

test ! -e "$root/etc/systemd/system/link5copy.service"

"$systemctl" --root="$root" link '/link5copy.service'
islink "$root/etc/systemd/system/link5copy.service" '/link5copy.service'
test ! -h "$root/etc/systemd/system/link5alias.service"
test ! -h "$root/etc/systemd/system/link5alias2.service"

# FIXME: we must create link5alias2 and link5alias as relative links to link5.service
# When they are independent links to /link5.service, systemd doesn't know that
# they are aliases, because we do not follow symlinks outside of the search paths.

"$systemctl" --root="$root" disable 'link5copy.service'
test ! -h "$root/etc/systemd/system/link5copy.service"
test ! -h "$root/etc/systemd/system/link5alias.service"
test ! -h "$root/etc/systemd/system/link5alias2.service"

"$systemctl" --root="$root" enable '/link5copy.service'
islink "$root/etc/systemd/system/link5copy.service" '/link5copy.service'
islink "$root/etc/systemd/system/link5alias.service" '/link5copy.service'
islink "$root/etc/systemd/system/link5alias2.service" '/link5copy.service'

"$systemctl" --root="$root" disable 'link5copy.service'
test ! -h "$root/etc/systemd/system/link5copy.service"
test ! -h "$root/etc/systemd/system/link5alias.service"
test ! -h "$root/etc/systemd/system/link5alias2.service"

: '-------issue 19437: plain templates in .wants/ or .requires/---'
test ! -e "$root/etc/systemd/system/link5@.path"
cat >"$root/etc/systemd/system/link5@.path" <<EOF
[Install]
WantedBy=target5@.target
RequiredBy=target5@.target
WantedBy=target5@inst.target
RequiredBy=target5@inst.target
EOF

"$systemctl" --root="$root" enable 'link5@.path'
test ! -h "$root/etc/systemd/system/link5@.path"  # this is our file
islink "$root/etc/systemd/system/target5@.target.wants/link5@.path" "/etc/systemd/system/link5@.path"
islink "$root/etc/systemd/system/target5@.target.requires/link5@.path" "/etc/systemd/system/link5@.path"
islink "$root/etc/systemd/system/target5@inst.target.wants/link5@.path" "/etc/systemd/system/link5@.path"
islink "$root/etc/systemd/system/target5@inst.target.requires/link5@.path" "/etc/systemd/system/link5@.path"

"$systemctl" --root="$root" disable 'link5@.path'
test ! -h "$root/etc/systemd/system/link5@.path"  # this is our file
test ! -h "$root/etc/systemd/system/target5@.target.wants/link5@.path"
test ! -h "$root/etc/systemd/system/target5@.target.requires/link5@.path"
test ! -h "$root/etc/systemd/system/target5@inst.target.wants/link5@.path"
test ! -h "$root/etc/systemd/system/target5@inst.target.requires/link5@.path"

: '-------removal of symlinks not listed in [Install]-------------'
# c.f. 66a19d85a533b15ed32f4066ec880b5a8c06babd
test ! -e "$root/etc/systemd/system/multilink.mount"
cat >"$root/etc/systemd/system/multilink.mount" <<EOF
[Install]
WantedBy=multilink.target
EOF

mkdir -p "$root/etc/systemd/system/default.target.wants"
ln -s ../multilink.mount "$root/etc/systemd/system/default.target.wants/"
ln -s ../multilink.mount "$root/etc/systemd/system/multilink-alias.mount"
ln -s ../multilink.mount "$root/etc/systemd/system/multilink-badalias.service"

"$systemctl" --root="$root" disable 'multilink.mount'
test -e "$root/etc/systemd/system/multilink.mount"  # this is our file
test ! -h "$root/etc/systemd/system/default.target.wants/"
test ! -h "$root/etc/systemd/system/multilink-alias.mount"
test ! -h "$root/etc/systemd/system/multilink-badalias.service"

: '-------merge 20017: specifiers in the unit file----------------'
test ! -e "$root/etc/systemd/system/some-some-link6@.socket"
# c.f. de61a04b188f81a85cdb5c64ddb4987dcd9d30d3

check_alias() {
    : "------------------ %$1 -------------------------------------"
    cat >"$root/etc/systemd/system/some-some-link6@.socket" <<EOF
[Install]
Alias=target@$1:%$1.socket
EOF
    SYSTEMD_LOG_LEVEL=debug "$systemctl" --root="$root" enable 'some-some-link6@.socket' || return 1
    islink "$root/etc/systemd/system/target@$1:$2.socket" "/etc/systemd/system/some-some-link6@.socket" || return 2
}

# TODO: our architecture names are different than what uname -m returns.
# Add something like 'systemd-detect-virt --print-architecture' and use it here.
check_alias a "$(uname -m | tr '_' '-')" || :

test ! -e "$root/etc/os-release"
test ! -e "$root/usr/lib/os-release"

( ! check_alias A '' )
( ! check_alias B '' )
( ! check_alias M '' )
( ! check_alias o '' )
( ! check_alias w '' )
( ! check_alias W '' )

cat >"$root/etc/os-release" <<EOF
# empty
EOF

check_alias A ''
check_alias B ''
check_alias M ''
check_alias o ''
check_alias w ''
check_alias W ''

cat >"$root/etc/os-release" <<EOF
ID='the-id'
VERSION_ID=39a
BUILD_ID=build-id
VARIANT_ID=wrong
VARIANT_ID=right
IMAGE_ID="foobar"
IMAGE_VERSION='1-2-3'
EOF

check_alias A '1-2-3'
check_alias B 'build-id'
check_alias M 'foobar'
check_alias o 'the-id'
check_alias w '39a'
check_alias W 'right'

check_alias b "$("$systemd_id128" boot-id)"

# Specifiers not available for [Install]
( ! check_alias C '' )
( ! check_alias E '' )
( ! check_alias f '' )
( ! check_alias h '' )
( ! check_alias I '' )
( ! check_alias J '' )
( ! check_alias L '' )
( ! check_alias P '' )
( ! check_alias s '' )
( ! check_alias S '' )
( ! check_alias t '' )
( ! check_alias T '' )
( ! check_alias V '' )

check_alias g root
check_alias G 0
check_alias u root
check_alias U 0

check_alias i ""

check_alias j 'link6'

check_alias l "$(uname -n | sed 's/\..*//')"

test ! -e "$root/etc/machine-id"
( ! check_alias m '' )

"$systemd_id128" new >"$root/etc/machine-id"
check_alias m "$(cat "$root/etc/machine-id")"

check_alias n 'some-some-link6@.socket'
check_alias N 'some-some-link6@'

check_alias p 'some-some-link6'

uname -r | grep -q '[^a-zA-Z0-9_.\\-]' || \
    check_alias v "$(uname -r)"

# % is not legal in unit name
( ! check_alias % '%' )

# %z is not defined
( ! check_alias z 'z' )

: '-------specifiers in WantedBy----------------------------------'
# We don't need to repeat all the tests. Let's do a basic check that specifier
# expansion is performed.

cat >"$root/etc/systemd/system/some-some-link7.socket" <<EOF
[Install]
WantedBy=target@%p.target
WantedBy=another-target@.target
RequiredBy=target2@%p.target
RequiredBy=another-target2@.target
EOF

"$systemctl" --root="$root" enable 'some-some-link7.socket'
islink "$root/etc/systemd/system/target@some-some-link7.target.wants/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"
islink "$root/etc/systemd/system/another-target@.target.wants/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"
islink "$root/etc/systemd/system/target2@some-some-link7.target.requires/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"
islink "$root/etc/systemd/system/another-target2@.target.requires/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"

"$systemctl" --root="$root" disable 'some-some-link7.socket'
test ! -h "$root/etc/systemd/system/target@some-some-link7.target.wants/some-some-link7.socket"
test ! -h "$root/etc/systemd/system/another-target@.target.wants/some-some-link7.socket"
test ! -h "$root/etc/systemd/system/target2@some-some-link7.target.requires/some-some-link7.socket"
test ! -h "$root/etc/systemd/system/another-target2@.target.requires/some-some-link7.socket"

# TODO: repeat the tests above for presets

: '-------SYSTEMD_OS_RELEASE relative to root---------------------'
# check that os-release overwriting works as expected with root
test -e "$root/etc/os-release"

cat >"$root/etc/os-release2" <<EOF
ID='the-id2'
EOF

SYSTEMD_OS_RELEASE="/etc/os-release2" check_alias o 'the-id2'
