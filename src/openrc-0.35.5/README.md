OpenRC README
=============

OpenRC is a dependency-based init system that works with the
system-provided init program, normally `/sbin/init`. Currently, it does
not have an init program of its own.

## Installation

OpenRC requires GNU make.

Once you have GNU Make installed, the default OpenRC installation can be
executed using this command:

make install

## Configuration

You may wish to configure the installation by passing one or more of the
below arguments to the make command

```
PROGLDFLAGS=-static
LIBNAME=lib64
DESTDIR=/tmp/openrc-image
MKBASHCOMP=no
MKNET=no
MKPAM=pam
MKPREFIX=yes
MKPKGCONFIG=no
MKSELINUX=yes
MKSTATICLIBS=no
MKSYSVINIT=yes
MKTERMCAP=ncurses
MKTERMCAP=termcap
MKZSHCOMP=no
PKG_PREFIX=/usr/pkg
LOCAL_PREFIX=/usr/local
PREFIX=/usr/local
BRANDING=\"Gentoo/$(uname -s)\"
```

## Notes

We don't support building a static OpenRC with PAM.

You may need to use `PROGLDFLAGS=-Wl,-Bstatic` on glibc instead of just `-static`.

If you are building OpenRC for a Gentoo Prefix installation, add `MKPREFIX=yes`.

`PKG_PREFIX` should be set to where packages install to by default.

`LOCAL_PREFIX` should be set when to where user maintained packages are.
Only set `LOCAL_PREFIX` if different from `PKG_PREFIX`.

`PREFIX` should be set when OpenRC is not installed to /.

If any of the following files exist then we do not overwrite them

```
/etc/devd.conf
/etc/rc
/etc/rc.shutdown
/etc/conf.d/*
```

`rc` and `rc.shutdown` are the hooks from the BSD init into OpenRC.

`devd.conf` is modified from FreeBSD to call `/etc/rc.devd` which is a
generic hook into OpenRC.

`inittab` is the same, but for SysVInit as used by most Linux distributions.
This can be found in the support folder.

Obviously, if you're installing this onto a system that does not use
OpenRC by default then you may wish to backup the above listed files,
remove them and then install so that the OS hooks into OpenRC.

## Reporting Bugs

If you are using Gentoo Linux, bugs can be filed on their bugzilla under
the `gentoo hosted projects` product and the `openrc` component [1].
Otherwise, you can report issues on our github [2].

Better yet, if you can contribute code, please feel free to submit pull
requests [3].

## IRC Channel

We have an official irc channel, #openrc on freenode, feel free to join
us there.

[1]	https://bugs.gentoo.org/
[2]	https://github.com/openrc/openrc/issues
[3]	https://github.com/openrc/openrc/pulls
