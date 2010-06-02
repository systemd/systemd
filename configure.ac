#  This file is part of systemd.
#
#  Copyright 2010 Lennart Poettering
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.63)

AC_INIT([systemd],[0],[systemd-devel@lists.freedesktop.org])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax subdir-objects])

AC_SUBST(PACKAGE_URL, [http://www.freedesktop.org/wiki/Software/systemd])

AC_CANONICAL_HOST

AM_SILENT_RULES([yes])

AC_CHECK_PROG([STOW], [stow], [yes], [no])

AS_IF([test "x$STOW" = "xyes" && test -d /usr/local/stow], [
        AC_MSG_NOTICE([*** Found /usr/local/stow: default install prefix set to /usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION} ***])
        ac_default_prefix="/usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION}"
])

AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL
AC_USE_SYSTEM_EXTENSIONS

CC_CHECK_CFLAGS_APPEND([ \
        -Wall \
        -W \
        -Wextra \
        -pipe \
        -Wno-long-long \
        -Winline \
        -Wvla \
        -Wno-overlength-strings \
        -Wundef \
        -Wformat=2 \
        -Wlogical-op \
        -Wsign-compare \
        -Wformat-security \
        -Wmissing-include-dirs \
        -Wformat-nonliteral \
        -Wold-style-definition \
        -Wpointer-arith \
        -Winit-self \
        -Wdeclaration-after-statement \
        -Wfloat-equal \
        -Wmissing-prototypes \
        -Wstrict-prototypes \
        -Wredundant-decls \
        -Wmissing-declarations \
        -Wmissing-noreturn \
        -Wshadow \
        -Wendif-labels \
        -Wcast-align \
        -Wstrict-aliasing=2 \
        -Wwrite-strings \
        -Wno-unused-parameter \
        -ffast-math \
        -Wp,-D_FORTIFY_SOURCE=2 \
        -fno-common \
        -fdiagnostics-show-option \
        -Wno-missing-field-initializers])

AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([*** POSIX RT library not found])])
AC_SEARCH_LIBS([cap_init], [cap], [], [AC_MSG_ERROR([*** POSIX caps library not found])])
AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])

# This makes sure pkg.m4 is available.
m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

PKG_CHECK_MODULES(UDEV, [ libudev >= 154 ])
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)

PKG_CHECK_MODULES(DBUS, [ dbus-1 ])
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(DBUSGLIB, [ dbus-glib-1 ])
AC_SUBST(DBUSGLIB_CFLAGS)
AC_SUBST(DBUSGLIB_LIBS)

PKG_CHECK_MODULES(CGROUP, [ libcgroup >= 0.36 ])
AC_SUBST(CGROUP_CFLAGS)
AC_SUBST(CGROUP_LIBS)

have_gtk=no
AC_ARG_ENABLE(gtk, AS_HELP_STRING([--disable-gtk], [disable GTK tools]))
if test "x$enable_gtk" != "xno"; then
        PKG_CHECK_MODULES(GTK, [ gtk+-2.0 ],
                [AC_DEFINE(HAVE_GTK, 1, [Define if GTK is available]) have_gtk=yes], have_gtk=no)
        AC_SUBST(GTK_CFLAGS)
        AC_SUBST(GTK_LIBS)
        if test "x$have_gtk" = xno -a "x$enable_gtk" = xyes; then
             AC_MSG_ERROR([*** gtk support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_GTK, [test "$have_gtk" = "yes"])

AM_PROG_VALAC([0.8])
AC_SUBST(VAPIDIR)
AM_CONDITIONAL(HAVE_VALAC, test x"$VALAC" != x)

AC_PATH_PROG([XSLTPROC], [xsltproc])
AM_CONDITIONAL(HAVE_XSLTPROC, test x"$XSLTPROC" != x)

AC_PATH_PROG([M4], [m4])

AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO],[Specify the distribution to target: One of fedora, suse, debian, arch, gentoo, slackware or other]))
if test "z$with_distro" = "z"; then
        if test "$cross_compiling" = yes; then
                AC_MSG_WARN([Target distribution cannot be reliably detected when cross-compiling. You should specify it with --with-distro (see $0 --help for recognized distros)])
        else
                AC_CHECK_FILE(/etc/redhat-release,with_distro="fedora")
                AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
                AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
                AC_CHECK_FILE(/etc/arch-release,with_distro="arch")
                AC_CHECK_FILE(/etc/gentoo-release,with_distro="gentoo")
                AC_CHECK_FILE(/etc/slackware-version,with_distro="slackware")
        fi
        if test "z$with_distro" = "z"; then
                with_distro=`uname -s`
        fi
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]' `

# Default generic names
SPECIAL_DBUS_SERVICE=dbus.service
SPECIAL_SYSLOG_SERVICE=syslog.service

# Location of the init scripts as mandated by LSB
SYSTEM_SYSVINIT_PATH=/etc/init.d

M4_DISTRO_FLAG=

case $with_distro in
        fedora)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                SYSTEM_SYSVRCND_PATH=/etc/rc.d

                # A little background why we define these special unit
                # names here in configure.ac: SysV services currently
                # cannot have aliases. As long as syslog is started
                # via a SysV init script we hence define these names
                # to the actual SysV name here. Later on when SysV
                # init scripts are not used anymore it is advisable to
                # use the generic names instead and use symlinks in
                # the unit directories to point to the right native
                # unit file.

                SPECIAL_DBUS_SERVICE=messagebus.service
                SPECIAL_SYSLOG_SERVICE=rsyslog.service
                AC_DEFINE(TARGET_FEDORA, [], [Target is Fedora/RHEL])
                M4_DISTRO_FLAG=-DTARGET_FEDORA=1
                ;;
        suse)
                SYSTEM_SYSVRCND_PATH=/etc/init.d
                AC_DEFINE(TARGET_SUSE, [], [Target is OpenSUSE/SLE])
                M4_DISTRO_FLAG=-DTARGET_SUSE=1
                ;;
        debian)
                SYSTEM_SYSVRCND_PATH=/etc
                SPECIAL_SYSLOG_SERVICE=rsyslog.service
                AC_DEFINE(TARGET_DEBIAN, [], [Target is Debian/Ubuntu])
                M4_DISTRO_FLAG=-DTARGET_DEBIAN=1
                ;;
        arch)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d
                SYSTEM_SYSVRCND_PATH=/etc
                SPECIAL_SYSLOG_SERVICE=syslog-ng.service
                AC_DEFINE(TARGET_ARCH, [], [Target is ArchLinux])
                M4_DISTRO_FLAG=-DTARGET_ARCH=1
                ;;
        gentoo)
                SYSTEM_SYSVRCND_PATH=/etc
                SPECIAL_SYSLOG_SERVICE=syslog-ng.service
                AC_DEFINE(TARGET_GENTOO, [], [Target is Gentoo])
                M4_DISTRO_FLAG=-DTARGET_GENTOO=1
                ;;
        slackware)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                SYSTEM_SYSVRCND_PATH=/etc/rc.d
                SPECIAL_DBUS_SERVICE=messagebus.service
                AC_DEFINE(TARGET_SLACKWARE, [], [Target is Slackware])
                M4_DISTRO_FLAG=-DTARGET_SLACKWARE=1
                ;;
        other)
                AS_IF([test "x$with_sysvinit_path" = "x"],
                        [AC_MSG_ERROR([With --distro=other, you must pass --with-sysvinit-path= to configure])])
                AS_IF([test "x$with_sysvrcd_path" = "x"],
                        [AC_MSG_ERROR([With --distro=other, you must pass --with-sysvrcd-path= to configure])])
                AS_IF([test "x$with_dbus_service" = "x"],
                        [AC_MSG_ERROR([With --distro=other, you must pass --with-dbus-service= to configure])])
                AS_IF([test "x$with_syslog_service" = "x"],
                        [AC_MSG_ERROR([With --distro=other, you must pass --with-syslog-service= to configure])])
                ;;
        *)
                AC_MSG_ERROR([Your distribution (${with_distro}) is not yet supported, SysV init scripts could not be found! (patches welcome); you can specify --with-distro=other to skip this check])
                ;;
esac

AC_ARG_WITH([sysvinit-path],
	[AS_HELP_STRING([--with-sysvinit-path=PATH],
		[Specify the path to where the SysV init scripts are located @<:@default=based on distro@:>@])],
	[SYSTEM_SYSVINIT_PATH="$withval"],
	[])

AC_ARG_WITH([sysvrcd-path],
        [AS_HELP_STRING([--with-sysvrcd-path=PATH],
                [Specify the path to the base directory for the SysV rcN.d directories @<:@default=based on distro@:>@])],
        [SYSTEM_SYSVRCND_PATH="$withval"],
        [])

AC_ARG_WITH([dbus-service],
        [AS_HELP_STRING([--with-dbus-service=PATH],
                [Specify the name of the special DBus service @<:@default=based on distro@:>@])],
        [SPECIAL_DBUS_SERVICE="$withval"],
        [])

AC_ARG_WITH([syslog-service],
        [AS_HELP_STRING([--with-syslog-service=PATH],
                [Specify the name of the special syslog service @<:@default=based on distro@:>@])],
        [SPECIAL_SYSLOG_SERVICE="$withval"],
        [])

AC_SUBST(SYSTEM_SYSVINIT_PATH)
AC_SUBST(SYSTEM_SYSVRCND_PATH)
AC_SUBST(SPECIAL_DBUS_SERVICE)
AC_SUBST(SPECIAL_SYSLOG_SERVICE)
AC_SUBST(M4_DISTRO_FLAG)

AM_CONDITIONAL(TARGET_FEDORA, test x"$with_distro" = xfedora)
AM_CONDITIONAL(TARGET_SUSE, test x"$with_distro" = xsuse)
AM_CONDITIONAL(TARGET_DEBIAN, test x"$with_distro" = xdebian)
AM_CONDITIONAL(TARGET_ARCH, test x"$with_distro" = xarch)
AM_CONDITIONAL(TARGET_GENTOO, test x"$with_distro" = xgentoo)
AM_CONDITIONAL(TARGET_SLACKWARE, test x"$with_distro" = xslackware)

AC_DEFINE_UNQUOTED(SPECIAL_DBUS_SERVICE, ["$SPECIAL_DBUS_SERVICE"], [D-Bus service name])
AC_DEFINE_UNQUOTED(SPECIAL_SYSLOG_SERVICE, ["$SPECIAL_SYSLOG_SERVICE"], [Syslog service name])

AC_ARG_WITH([udevrulesdir],
        AS_HELP_STRING([--with-udevrulesdir=DIR], [Diectory for udev rules]),
        [],
        [with_udevrulesdir=/lib/udev/rules.d])
AC_SUBST([udevrulesdir], [$with_udevrulesdir])

AC_ARG_WITH([rootdir],
        AS_HELP_STRING([--with-rootdir=DIR], [Root directory for files necessary for boot]),
        [],
        [with_rootdir=${ac_default_prefix}])
AC_SUBST([rootdir], [$with_rootdir])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
        $PACKAGE_NAME $VERSION

        Distribution:            ${with_distro}
        SysV init scripts:       ${SYSTEM_SYSVINIT_PATH}
        SysV rc?.d directories:  ${SYSTEM_SYSVRCND_PATH}
        Syslog service:          ${SPECIAL_SYSLOG_SERVICE}
        D-Bus service:           ${SPECIAL_DBUS_SERVICE}
        Gtk:                     ${have_gtk}
        prefix:                  ${prefix}
        root dir:                ${with_rootdir}
        udev rules dir:          ${with_udevrulesdir}
"
