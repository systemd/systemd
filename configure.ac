# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# This file is part of nss-myhostname.
#
# Copyright 2008 Lennart Poettering
#
# nss-myhostname is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# nss-myhostname is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with nss-myhostname. If not, If not, see
# <http://www.gnu.org/licenses/>.

AC_PREREQ(2.62)
AC_INIT([nss-myhostname],[0.3],[mzzlubfganzr (at) 0pointer (dot) de])
AC_CONFIG_SRCDIR([nss-myhostname.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR(m4)
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AM_INIT_AUTOMAKE([foreign 1.9 -Wall -Wno-portability silent-rules tar-pax subdir-objects dist-bzip2])

AC_SUBST(PACKAGE_URL, [http://0pointer.de/lennart/projects/nss-myhostname/])

ac_default_prefix="/"

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CPP

AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# GCC flags

DESIRED_FLAGS="-Wall -W -Wextra -pedantic -pipe -Wformat -Wold-style-definition -Wdeclaration-after-statement -Wfloat-equal -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wpointer-arith -Wcast-align -Wwrite-strings -Winline -Wno-unused-parameter -ffast-math -fvisibility=hidden -fdiagnostics-show-option"

for flag in $DESIRED_FLAGS ; do
  CC_CHECK_CFLAGS([$flag], [CFLAGS="$CFLAGS $flag"])
done

# libtool stuff
AC_DISABLE_STATIC
LT_PREREQ(2.2)
LT_INIT

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h nss.h sys/ioctl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([gethostbyaddr gethostbyname gettimeofday inet_ntoa memset select socket strcspn strdup strerror strncasecmp strcasecmp strspn])

# LYNX documentation generation
ZP_LYNX_DOC

AC_CONFIG_FILES([Makefile doc/Makefile doc/README.html ])

AC_OUTPUT
