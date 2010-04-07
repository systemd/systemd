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

AC_INIT([systemd],[0],[mzflfgrzq (at) 0pointer (dot) net])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax])

AC_SUBST(PACKAGE_URL, [http://git.0pointer.de/?p=systemd.git])

AC_CANONICAL_HOST

AM_SILENT_RULES([yes])

AC_CHECK_PROG([STOW], [stow], [yes], [no])

AS_IF([test "x$STOW" = "xyes" && test -d /usr/local/stow], [
        AC_MSG_NOTICE([*** Found /usr/local/stow: default install prefix set to /usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION} ***])
        ac_default_prefix="/usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION}"
])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL
AC_USE_SYSTEM_EXTENSIONS

CC_CHECK_CFLAGS_APPEND([-Wall -W -Wextra -pipe -Wno-long-long -Winline -Wvla -Wno-overlength-strings -Wundef -Wformat=2 -Wlogical-op -Wsign-compare -Wformat-security -Wmissing-include-dirs -Wformat-nonliteral -Wold-style-definition -Wpointer-arith -Winit-self -Wdeclaration-after-statement -Wfloat-equal -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-declarations -Wmissing-noreturn -Wshadow -Wendif-labels -Wcast-align -Wstrict-aliasing=2 -Wwrite-strings -Wno-unused-parameter -ffast-math -Wp,-D_FORTIFY_SOURCE=2 -fno-common -fdiagnostics-show-option -Wno-missing-field-initializers])

AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([*** POSIX RT library not found])])
AC_SEARCH_LIBS([cap_init], [cap], [], [AC_MSG_ERROR([*** POSIX caps library not found])])
AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])

PKG_CHECK_MODULES(UDEV, [ libudev ])
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)

PKG_CHECK_MODULES(DBUS, [ dbus-1 ])
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(DBUSGLIB, [ dbus-glib-1 ])
AC_SUBST(DBUSGLIB_CFLAGS)
AC_SUBST(DBUSGLIB_LIBS)

PKG_CHECK_MODULES(GEE, [ gee-1.0 ])
AC_SUBST(GEE_CFLAGS)
AC_SUBST(GEE_LIBS)

PKG_CHECK_MODULES(GTK, [ gtk+-2.0 ])
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

PKG_CHECK_MODULES(CGROUP, [ libcgroup ])
AC_SUBST(CGROUP_CFLAGS)
AC_SUBST(CGROUP_LIBS)

AM_PROG_VALAC()
AC_SUBST(VAPIDIR)

AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO],[Specify the distribution to target: One of fedora, suse, debian, or none]))
if test "z$with_distro" = "z"; then
        if test "$cross_compiling" = yes; then
                AC_MSG_WARN([Target distribution cannot be reliably detected when cross-compiling. You should specify it with --with-distro (see $0 --help for recognized distros)])
        else
                AC_CHECK_FILE(/etc/redhat-release,with_distro="fedora")
                AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
                AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
        fi
        if test "z$with_distro" = "z"; then
                with_distro=`uname -s`
        fi
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]' `

echo "hallo"

case $with_distro in
        fedora)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                SYSTEM_SYSVRCND_PATH=/etc/rc.d
                ;;
        suse)
                SYSTEM_SYSVINIT_PATH=/etc/init.d
                SYSTEM_SYSVRCND_PATH=/etc/init.d
                ;;
        debian)
                SYSTEM_SYSVINIT_PATH=/etc/init.d
                SYSTEM_SYSVRCND_PATH=/etc
                ;;
        none)
                SYSTEM_SYSVINIT_PATH=/etc/fix/the/configure/script
                SYSTEM_SYSVRCND_PATH=/etc/fix/the/configure/script
                ;;
        *)
                AC_MSG_ERROR([Your distribution (${with_distro}) is not yet supported, SysV init scripts could not be found! (patches welcome); you can specify --with-distro=none to skip this check])
                ;;
esac

echo "hallo"

AC_SUBST(SYSTEM_SYSVINIT_PATH)
AC_SUBST(SYSTEM_RCND_PATH)

AM_CONDITIONAL(TARGET_FEDORA, test x"$with_distro" = xfedora)
AM_CONDITIONAL(TARGET_SUSE, test x"$with_distro" = xsuse)
AM_CONDITIONAL(TARGET_DEBIAN, test x"$with_distro" = xdebian)

AC_OUTPUT([Makefile])

echo "
        $PACKAGE_NAME $VERSION

        SysV init scripts:       ${SYSTEM_SYSVINIT_PATH}
        SysV rc?.d directories:  ${SYSTEM_SYSVRCND_PATH}
"
