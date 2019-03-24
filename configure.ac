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

AC_INIT([systemd-ui],[3],[systemd-devel@lists.freedesktop.org])
AC_CONFIG_SRCDIR([src/systemadm.vala])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PREFIX_DEFAULT([/usr])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects])
AC_SUBST(PACKAGE_URL, [http://www.freedesktop.org/wiki/Software/systemd])
AC_CANONICAL_HOST
AM_SILENT_RULES([yes])
AC_SUBST(GETTEXT_PACKAGE)
AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL

AC_PATH_PROG([XSLTPROC], [xsltproc])
AM_CONDITIONAL(HAVE_XSLTPROC, test x"$XSLTPROC" != x)

CC_CHECK_CFLAGS_APPEND([ \
        -pipe \
        -Wall \
        -W \
        -Wextra \
        -Wno-inline \
        -Wvla \
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
        -Wmissing-declarations \
        -Wmissing-noreturn \
        -Wshadow \
        -Wendif-labels \
        -Wcast-align \
        -Wstrict-aliasing=2 \
        -Wwrite-strings \
        -Wno-long-long \
        -Wno-overlength-strings \
        -Wno-unused-parameter \
        -Wno-missing-field-initializers \
        -Wno-unused-result \
        -Wno-unused-but-set-variable \
        -Werror=overflow \
        -Wp,-D_FORTIFY_SOURCE=2 \
        -ffast-math \
        -fno-common \
        -fdiagnostics-show-option \
        -fno-strict-aliasing \
        -fvisibility=hidden \
        -ffunction-sections \
        -fdata-sections \
        -Wl,--as-needed \
        -Wl,--gc-sections])

# This makes sure pkg.m4 is available.
m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([*** POSIX RT library not found])])

PKG_CHECK_MODULES(DBUS, [ dbus-1 >= 1.3.2 ])
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(GTK, [ gtk+-3.0 glib-2.0 > 2.26 gio-unix-2.0 ])
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

PKG_CHECK_MODULES(GEE, [ gee-0.8 ],,
        [AC_MSG_WARN([gee-0.8 not found, falling back to older version])])
AS_IF([test -n "$GEE_LIBS"],
        [AC_SUBST(GEE_PACKAGE, [gee-0.8])],
        [PKG_CHECK_MODULES(GEE, [ gee-1.0 ])
         AC_SUBST(GEE_PACKAGE, [gee-1.0])]
)
AC_SUBST(GEE_CFLAGS)
AC_SUBST(GEE_LIBS)

PKG_CHECK_MODULES(LIBNOTIFY, [ libnotify ])
AC_SUBST(LIBNOTIFY_CFLAGS)
AC_SUBST(LIBNOTIFY_LIBS)

AM_PROG_VALAC([0.10])
AC_SUBST(VAPIDIR)
AM_CONDITIONAL(HAVE_VALAC, test x"$VALAC" != x)

AC_PATH_PROG([M4], [m4])
AC_SUBST(M4_DEFINES)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE_NAME $VERSION

        prefix:                  ${prefix}
])
