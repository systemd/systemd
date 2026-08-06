#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

# Silence warning from running_in_chroot_or_offline()
export SYSTEMD_IN_CHROOT=0

systemctl=${1:-systemctl}
systemd_id128=${2:-systemd-id128}

unset root vroot
cleanup() {
    [ -n "$root" ] && rm -rf "$root"
    [ -n "$vroot" ] && rm -rf "$vroot"
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
islink "$root/etc/systemd/system/link5alias.service" '/etc/systemd/system/link5copy.service'
islink "$root/etc/systemd/system/link5alias2.service" '/etc/systemd/system/link5copy.service'

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

: '-------specifiers in presets------------------------------------'
# Repeat the check above, but via 'systemctl preset' instead
# of calling enable/disable directly. We reuse the same unit file, which is
# currently disabled (no symlinks) from the block above.

mkdir -p "$root/etc/systemd/system-preset"
cat >"$root/etc/systemd/system-preset/99-test.preset" <<EOF
enable some-some-link7.socket
EOF

"$systemctl" --root="$root" preset 'some-some-link7.socket'
islink "$root/etc/systemd/system/target@some-some-link7.target.wants/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"
islink "$root/etc/systemd/system/another-target@.target.wants/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"
islink "$root/etc/systemd/system/target2@some-some-link7.target.requires/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"
islink "$root/etc/systemd/system/another-target2@.target.requires/some-some-link7.socket" "/etc/systemd/system/some-some-link7.socket"

cat >"$root/etc/systemd/system-preset/99-test.preset" <<EOF
disable some-some-link7.socket
EOF

"$systemctl" --root="$root" preset 'some-some-link7.socket'
test ! -h "$root/etc/systemd/system/target@some-some-link7.target.wants/some-some-link7.socket"
test ! -h "$root/etc/systemd/system/another-target@.target.wants/some-some-link7.socket"
test ! -h "$root/etc/systemd/system/target2@some-some-link7.target.requires/some-some-link7.socket"
test ! -h "$root/etc/systemd/system/another-target2@.target.requires/some-some-link7.socket"

# Not testing preset-all here: $root has leftover units from earlier
# sections that are deliberately invalid, and preset-all trips on those.

# Clean up so later tests aren't affected by this preset file.
rm -f "$root/etc/systemd/system-preset/99-test.preset"

: '-------SYSTEMD_OS_RELEASE relative to root---------------------'
# check that os-release overwriting works as expected with root
test -e "$root/etc/os-release"

cat >"$root/etc/os-release2" <<EOF
ID='the-id2'
EOF

SYSTEMD_OS_RELEASE="/etc/os-release2" check_alias o 'the-id2'

: '-------is-enabled --full is relative to --root=-----------------'
mkdir -p "$root/usr/lib/systemd/system"
cat >"$root/usr/lib/systemd/system/rooted.service" <<EOF2
[Install]
WantedBy=multi-user.target
EOF2
"$systemctl" --root="$root" enable rooted.service

# Without --root= being passed on this inspects the host, which knows nothing about this unit.
"$systemctl" --root="$root" is-enabled --full rooted.service |
    grep "^  $root/etc/systemd/system/multi-user.target.wants/rooted.service\$" >/dev/null

: '-------vendor enablement---------------------------------------'
mkdir -p "$root/usr/lib/systemd/system"
cat >"$root/usr/lib/systemd/system/vendor1.service" <<EOF2
[Install]
WantedBy=multi-user.target
EOF2

# "preset --vendor" installs into /usr/, leaving /etc/ untouched.
mkdir -p "$root/usr/lib/systemd/system-preset"
cat >"$root/usr/lib/systemd/system-preset/50-vendor.preset" <<EOF2
enable vendor1.service
EOF2

"$systemctl" --root="$root" --vendor preset vendor1.service
test -h "$root/usr/lib/systemd/system/multi-user.target.wants/vendor1.service"
test ! -h "$root/etc/systemd/system/multi-user.target.wants/vendor1.service"
test "$("$systemctl" --root="$root" is-enabled vendor1.service)" = "enabled"

# The administrator can still turn it off, which shadows the vendor symlink from /etc/.
"$systemctl" --root="$root" disable vendor1.service
islink "$root/etc/systemd/system/multi-user.target.wants/vendor1.service" /dev/null
test -h "$root/usr/lib/systemd/system/multi-user.target.wants/vendor1.service"
test "$("$systemctl" --root="$root" is-enabled vendor1.service)" = "disabled"

# Disabling twice must not undo the mask.
"$systemctl" --root="$root" disable vendor1.service
islink "$root/etc/systemd/system/multi-user.target.wants/vendor1.service" /dev/null

# Enabling drops the mask again, leaving a real enablement symlink behind.
"$systemctl" --root="$root" enable vendor1.service
test -h "$root/etc/systemd/system/multi-user.target.wants/vendor1.service"
test "$(readlink "$root/etc/systemd/system/multi-user.target.wants/vendor1.service")" != /dev/null
test "$("$systemctl" --root="$root" is-enabled vendor1.service)" = "enabled"

# "disable --vendor" removes the symlink outright: there is nothing above /usr/ to mask it from.
"$systemctl" --root="$root" disable vendor1.service
"$systemctl" --root="$root" --vendor disable vendor1.service
test ! -h "$root/usr/lib/systemd/system/multi-user.target.wants/vendor1.service"
rm -f "$root/usr/lib/systemd/system-preset/50-vendor.preset"

: '-------vendor enablement of a static unit----------------------'
# A unit without [Install] is wired up statically by its vendor symlink, not enabled by it, so it must
# neither be reported as enabled nor be maskable.
cat >"$root/usr/lib/systemd/system/vendor2.service" <<EOF2
[Unit]
Description=no Install section
EOF2
mkdir -p "$root/usr/lib/systemd/system/sysinit.target.wants"
ln -s ../vendor2.service "$root/usr/lib/systemd/system/sysinit.target.wants/vendor2.service"

test "$("$systemctl" --root="$root" is-enabled vendor2.service)" = "static"
"$systemctl" --root="$root" disable vendor2.service
test ! -h "$root/etc/systemd/system/sysinit.target.wants/vendor2.service"

: '-------vendor symlinks nobody asked for------------------------'
# Distributions ship default.target, the runlevel targets and various compatibility names below /usr/.
# Presetting into the vendor directories must leave every one of them where it is.
cat >"$root/usr/lib/systemd/system/vendor4.service" <<EOF2
[Install]
Alias=vendor4-slot.service
WantedBy=multi-user.target
EOF2
mkdir -p "$root/usr/lib/systemd/system/multi-user.target.wants"
ln -s vendor4.service "$root/usr/lib/systemd/system/vendor4-compat.service"
ln -s vendor4.service "$root/usr/lib/systemd/system/vendor4-slot.service"
ln -s ../vendor4.service "$root/usr/lib/systemd/system/multi-user.target.wants/vendor4.service"

cat >"$root/usr/lib/systemd/system-preset/50-vendor.preset" <<EOF2
disable vendor4.service
EOF2

"$systemctl" --root="$root" --vendor preset vendor4.service
test ! -h "$root/usr/lib/systemd/system/multi-user.target.wants/vendor4.service"
test -h "$root/usr/lib/systemd/system/vendor4-compat.service"
test -h "$root/usr/lib/systemd/system/vendor4-slot.service"

# An explicit disable may take back what enabling would have created, and only that.
"$systemctl" --root="$root" --vendor disable vendor4.service
test -h "$root/usr/lib/systemd/system/vendor4-compat.service"
test ! -h "$root/usr/lib/systemd/system/vendor4-slot.service"
rm -f "$root/usr/lib/systemd/system-preset/50-vendor.preset" \
      "$root/usr/lib/systemd/system/vendor4-compat.service"

: '-------vendor switch rejections--------------------------------'
( ! "$systemctl" --root="$root" --vendor --runtime enable vendor1.service )
( ! "$systemctl" --root="$root" --vendor --user enable vendor1.service )
( ! "$systemctl" --root="$root" --vendor mask vendor1.service )
( ! "$systemctl" --root="$root" --vendor is-enabled vendor1.service )

: '-------is-enabled --full reports the vendor symlink--------------'
mkdir -p "$root/usr/lib/systemd/system/multi-user.target.wants"
cat >"$root/usr/lib/systemd/system/vendor3.service" <<EOF2
[Install]
WantedBy=multi-user.target
EOF2
ln -s ../vendor3.service "$root/usr/lib/systemd/system/multi-user.target.wants/vendor3.service"

"$systemctl" --root="$root" is-enabled --full vendor3.service |
    grep "^  $root/usr/lib/systemd/system/multi-user.target.wants/vendor3.service\$" >/dev/null

: '-------vendor mode leaves static wiring alone------------------'
# A "disable *" policy applied to /usr/ must not take statically wired units out of the boot, and
# --vendor disable must still remove the Alias= symlink it created for such a unit.
vroot=$(mktemp -d --tmpdir systemctl-vendor.XXXXXX)
mkdir -p "$vroot/usr/lib/systemd/system/sysinit.target.wants" "$vroot/usr/lib/systemd/system-preset" "$vroot/etc/systemd/system"
cat >"$vroot/usr/lib/systemd/system/vstatic.service" <<EOF2
[Unit]
Description=statically wired
[Install]
Alias=vstatic-alias.service
EOF2
cat >"$vroot/usr/lib/systemd/system/venabled.service" <<EOF2
[Install]
WantedBy=sysinit.target
EOF2
ln -s ../vstatic.service "$vroot/usr/lib/systemd/system/sysinit.target.wants/vstatic.service"
ln -s ../venabled.service "$vroot/usr/lib/systemd/system/sysinit.target.wants/venabled.service"
echo 'disable *' >"$vroot/usr/lib/systemd/system-preset/99-off.preset"

"$systemctl" --root="$vroot" --vendor preset-all
test -h "$vroot/usr/lib/systemd/system/sysinit.target.wants/vstatic.service"
test ! -h "$vroot/usr/lib/systemd/system/sysinit.target.wants/venabled.service"
test ! -h "$vroot/etc/systemd/system/sysinit.target.wants/vstatic.service"

# --vendor enable/disable must round-trip an Alias= symlink even though the unit is statically wired:
# only the dependency directories are off limits.
"$systemctl" --root="$vroot" --vendor enable vstatic.service
test -h "$vroot/usr/lib/systemd/system/vstatic-alias.service"
"$systemctl" --root="$vroot" --vendor disable vstatic.service
test ! -h "$vroot/usr/lib/systemd/system/vstatic-alias.service"
test -h "$vroot/usr/lib/systemd/system/sysinit.target.wants/vstatic.service"

# The protection has to match the same way removal does, or an instance of a statically wired template,
# or an entry carrying the unit's Alias= name, slips through it.
cat >"$vroot/usr/lib/systemd/system/vtmpl@.service" <<EOF2
[Unit]
Description=statically wired template
EOF2
ln -s ../vtmpl@.service "$vroot/usr/lib/systemd/system/sysinit.target.wants/vtmpl@one.service"
ln -s ../vstatic.service "$vroot/usr/lib/systemd/system/sysinit.target.wants/vstatic-alias.service"

"$systemctl" --root="$vroot" --vendor preset-all
test -h "$vroot/usr/lib/systemd/system/sysinit.target.wants/vtmpl@one.service"
test -h "$vroot/usr/lib/systemd/system/sysinit.target.wants/vstatic-alias.service"

# A leftover pointing at a unit that no longer exists is not static wiring, it is rubbish to clean up.
ln -s ../vgone.service "$vroot/usr/lib/systemd/system/sysinit.target.wants/vgone.service"
"$systemctl" --root="$vroot" --vendor disable vgone.service || true
test ! -h "$vroot/usr/lib/systemd/system/sysinit.target.wants/vgone.service"
rm -f "$vroot/usr/lib/systemd/system/sysinit.target.wants/vstatic-alias.service"

: '-------enable keeps an administrator mask of a static unit-----'
mkdir -p "$vroot/etc/systemd/system/sysinit.target.wants"
ln -s /dev/null "$vroot/etc/systemd/system/sysinit.target.wants/vstatic.service"
"$systemctl" --root="$vroot" enable vstatic.service || true
islink "$vroot/etc/systemd/system/sysinit.target.wants/vstatic.service" /dev/null
"$systemctl" --root="$vroot" preset-all
islink "$vroot/etc/systemd/system/sysinit.target.wants/vstatic.service" /dev/null
rm -f "$vroot/etc/systemd/system/sysinit.target.wants/vstatic.service"

: '-------Also= does not override a sibling preset policy---------'
cat >"$vroot/usr/lib/systemd/system/vmain.service" <<EOF2
[Install]
WantedBy=sysinit.target
Also=vaux.socket
EOF2
cat >"$vroot/usr/lib/systemd/system/vaux.socket" <<EOF2
[Install]
WantedBy=sockets.target
EOF2
cat >"$vroot/usr/lib/systemd/system-preset/50-mixed.preset" <<EOF2
disable vmain.service
enable vaux.socket
EOF2
# Presetting the main unit must not drag the Also= unit into the removal set: it has a preset policy of its
# own, and by the time Also= would be expanded that policy has already been applied or is yet to be.
"$systemctl" --root="$vroot" enable vaux.socket
test "$("$systemctl" --root="$vroot" is-enabled vaux.socket)" = "enabled"
"$systemctl" --root="$vroot" preset vmain.service
test "$("$systemctl" --root="$vroot" is-enabled vmain.service)" = "disabled"
test "$("$systemctl" --root="$vroot" is-enabled vaux.socket)" = "enabled"

"$systemctl" --root="$vroot" preset-all
test "$("$systemctl" --root="$vroot" is-enabled vaux.socket)" = "enabled"
test "$("$systemctl" --root="$vroot" is-enabled vmain.service)" = "disabled"
rm -rf "$vroot"

: '-------querying must never write-------------------------------'
# is-enabled --full drives a dry run through the masking code; a regression there would disable
# units from a read-only query.
qroot=$(mktemp -d --tmpdir systemctl-query.XXXXXX)
mkdir -p "$qroot/usr/lib/systemd/system/multi-user.target.wants" "$qroot/etc/systemd/system"
cat >"$qroot/usr/lib/systemd/system/q1.service" <<EOF
[Install]
WantedBy=multi-user.target
EOF
ln -s ../q1.service "$qroot/usr/lib/systemd/system/multi-user.target.wants/q1.service"
before=$(find "$qroot/etc" | sort)
"$systemctl" --root="$qroot" is-enabled --full q1.service >/dev/null
"$systemctl" --root="$qroot" is-enabled q1.service >/dev/null
test "$(find "$qroot/etc" | sort)" = "$before"
rm -rf "$qroot"

: '-------empty file masks a dependency like /dev/null does-------'
# PID 1 treats a dependency symlink resolving to an empty file as a mask, so we must not offer to
# mask it a second time.
eroot=$(mktemp -d --tmpdir systemctl-empty.XXXXXX)
mkdir -p "$eroot/usr/lib/systemd/system/multi-user.target.wants" "$eroot/etc/systemd/system/multi-user.target.wants"
cat >"$eroot/usr/lib/systemd/system/e1.service" <<EOF
[Install]
WantedBy=multi-user.target
EOF
ln -s ../e1.service "$eroot/usr/lib/systemd/system/multi-user.target.wants/e1.service"
: >"$eroot/etc/empty"
ln -s /etc/empty "$eroot/etc/systemd/system/multi-user.target.wants/e1.service"
test "$("$systemctl" --root="$eroot" is-enabled e1.service)" = "disabled"

# The same, but as a plain empty file rather than a symlink to one: PID 1 honours both.
mkdir -p "$eroot/etc/systemd/system/sockets.target.wants"
cat >"$eroot/usr/lib/systemd/system/e2.service" <<EOF
[Install]
WantedBy=sockets.target
EOF
mkdir -p "$eroot/usr/lib/systemd/system/sockets.target.wants"
ln -s ../e2.service "$eroot/usr/lib/systemd/system/sockets.target.wants/e2.service"
: >"$eroot/etc/systemd/system/sockets.target.wants/e2.service"
test "$("$systemctl" --root="$eroot" is-enabled e2.service)" = "disabled"

# A non-empty regular file is not a mask, but it still shadows the vendor symlink, and PID 1 then
# ignores it for not being a symlink. Either way the unit is not pulled in.
printf 'junk\n' >"$eroot/etc/systemd/system/sockets.target.wants/e2.service"
test "$("$systemctl" --root="$eroot" is-enabled e2.service)" = "disabled"
rm -f "$eroot/etc/systemd/system/sockets.target.wants/e2.service"
# log_info() writes to stderr, so redirect or this captures nothing either way
test -z "$("$systemctl" --root="$eroot" disable e1.service 2>&1)"
rm -rf "$eroot"

: '-------no pointless mask inside the vendor directory-----------'
# --vendor writes to /usr/lib/systemd/system/, which is LOWER priority than /usr/local/lib/. A mask
# placed there would shadow nothing, so it must not be written at all.
lroot=$(mktemp -d --tmpdir systemctl-local.XXXXXX)
mkdir -p "$lroot/usr/local/lib/systemd/system/multi-user.target.wants" "$lroot/usr/lib/systemd/system" "$lroot/etc/systemd/system"
cat >"$lroot/usr/lib/systemd/system/l1.service" <<EOF
[Install]
WantedBy=multi-user.target
EOF
ln -s /usr/lib/systemd/system/l1.service "$lroot/usr/local/lib/systemd/system/multi-user.target.wants/l1.service"
"$systemctl" --root="$lroot" --vendor disable l1.service
test ! -h "$lroot/usr/lib/systemd/system/multi-user.target.wants/l1.service"
rm -rf "$lroot"

: '-------any entry shadows the vendor symlink below it------------'
# conf_files_list_strv() lets whatever sits in the higher priority dependency directory win, and
# PID 1 then ignores anything that is not a symlink. Our verdict has to agree.
sroot=$(mktemp -d --tmpdir systemctl-shadow.XXXXXX)
mkdir -p "$sroot/usr/lib/systemd/system/multi-user.target.wants" "$sroot/etc/systemd/system/multi-user.target.wants"
cat >"$sroot/usr/lib/systemd/system/s1.service" <<EOF
[Install]
WantedBy=multi-user.target
EOF
ln -s ../s1.service "$sroot/usr/lib/systemd/system/multi-user.target.wants/s1.service"
entry="$sroot/etc/systemd/system/multi-user.target.wants/s1.service"

test "$("$systemctl" --root="$sroot" is-enabled s1.service)" = "enabled"

printf 'junk\n' >"$entry"
test "$("$systemctl" --root="$sroot" is-enabled s1.service)" = "disabled"
rm -f "$entry"

mkdir "$entry"
test "$("$systemctl" --root="$sroot" is-enabled s1.service)" = "disabled"
rmdir "$entry"

# A dangling symlink is still a dependency as far as PID 1 is concerned.
ln -s ../nope.service "$entry"
test "$("$systemctl" --root="$sroot" is-enabled s1.service)" = "enabled"
rm -f "$entry"

# Since a non-symlink already shadows the vendor symlink, disable has nothing left to do there, and
# must not try to replace it: that would either fail or destroy whatever is sitting there.
mkdir "$entry"
"$systemctl" --root="$sroot" disable s1.service
test -d "$entry"
rmdir "$entry"

printf 'junk\n' >"$entry"
"$systemctl" --root="$sroot" disable s1.service
test "$(cat "$entry")" = "junk"
rm -f "$entry"
rm -rf "$sroot"
