#
#  This file is part of systemd.
#
#  Copyright 2010-2012 Lennart Poettering
#  Copyright 2010-2012 Kay Sievers
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.64])

AC_INIT([systemd],
        [215],
        [http://bugs.freedesktop.org/enter_bug.cgi?product=systemd],
        [systemd],
        [http://www.freedesktop.org/wiki/Software/systemd])

AC_CONFIG_SRCDIR([src/core/main.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PREFIX_DEFAULT([/usr])
AM_MAINTAINER_MODE([enable])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects])
AM_SILENT_RULES([yes])
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], "$host", [Canonical host string.])
AS_IF([test "x$host_cpu" = "xmips" || test "x$host_cpu" = "xmipsel" ||
       test "x$host_cpu" = "xmips64" || test "x$host_cpu" = "xmips64el"],
      [AC_DEFINE(ARCH_MIPS, [], [Whether on mips arch])])

LT_PREREQ(2.2)
LT_INIT([disable-static])

AS_IF([test "x$enable_static" = "xyes"], [AC_MSG_ERROR([--enable-static is not supported by systemd])])
AS_IF([test "x$enable_largefile" = "xno"], [AC_MSG_ERROR([--disable-largefile is not supported by systemd])])

# i18n stuff for the PolicyKit policy files

# Check whether intltool can be found, disable NLS otherwise
AC_CHECK_PROG(intltool_found, [intltool-merge], [yes], [no])
AS_IF([test x"$intltool_found" != xyes],
      [AS_IF([test x"$enable_nls" = xyes],
             [AC_MSG_ERROR([--enable-nls requested but intltool not found])],
             [AS_IF([test x"$enable_nls" != xno],
                    [AC_MSG_WARN([*** Disabling NLS support because intltool was not found])
                     enable_nls=no])
             ])
      ])

AM_NLS
AS_IF([test x"$enable_nls" != xno], [
    # intltoolize greps for '^(AC|IT)_PROG_INTLTOOL', so it needs to be on its own line
IT_PROG_INTLTOOL([0.40.0])
])

AS_IF([test -z "$INTLTOOL_POLICY_RULE"], [
    # If intltool is not available, provide a dummy rule to fail generation of %.policy files with a meaningful error message
    INTLTOOL_POLICY_RULE='%.policy: %.policy.in ; @echo "  ITMRG   " $@ && echo "*** intltool support required to build target $@" && false'
    AC_SUBST(INTLTOOL_POLICY_RULE)
])

GETTEXT_PACKAGE=systemd
AC_SUBST(GETTEXT_PACKAGE)

AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_GREP
AC_PROG_AWK

AC_PROG_CC_C99

AC_PATH_PROG([M4], [m4])
AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_PATH_PROG([QUOTAON], [quotaon], [/usr/sbin/quotaon], [$PATH:/usr/sbin:/sbin])
AC_PATH_PROG([QUOTACHECK], [quotacheck], [/usr/sbin/quotacheck], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([KILL], [kill], [/usr/bin/kill], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([KMOD], [kmod], [/usr/bin/kmod], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([KEXEC], [kexec], [/usr/sbin/kexec], [$PATH:/usr/sbin:/sbin])

AS_IF([! ln --relative --help > /dev/null 2>&1], [AC_MSG_ERROR([*** ln doesn't support --relative ***])])

M4_DEFINES=

# gtkdocize greps for '^GTK_DOC_CHECK', so it needs to be on its own line
m4_ifdef([GTK_DOC_CHECK], [
GTK_DOC_CHECK([1.18],[--flavour no-tmpl])],
         [AM_CONDITIONAL([ENABLE_GTK_DOC], [false])
          enable_gtk_doc=no])

AS_IF([test "x$enable_gtk_doc" = "xyes" -a "x$XSLTPROC" = x], [
        AC_MSG_ERROR([*** GTK doc requested but xsltproc not found])
])

m4_ifdef([GOBJECT_INTROSPECTION_CHECK], [
GOBJECT_INTROSPECTION_CHECK([1.31.1])
], [
   AM_CONDITIONAL([HAVE_INTROSPECTION], [false])
   enable_introspection=no])

AC_CHECK_TOOL(STRINGS, strings)
AC_CHECK_TOOL(GPERF, gperf)
if test -z "$GPERF" ; then
        AC_MSG_ERROR([*** gperf not found])
fi

# ------------------------------------------------------------------------------
address_sanitizer_cflags=
address_sanitizer_cppflags=
address_sanitizer_ldflags=
AC_ARG_ENABLE(address-sanitizer, AS_HELP_STRING([--enable-address-sanitizer], [enable -fsanitize=address]))
AS_IF([test "x$enable_address_sanitizer" = "xyes"], [
            CC_CHECK_FLAG_APPEND([with_as_cflags], [CFLAGS], [-fsanitize=address])
            AS_IF([test -z "$with_as_cflags"],
                  [AC_MSG_ERROR([*** -fsanitize=address is not supported])])
            address_sanitizer_cflags="$with_as_cflags -fno-omit-frame-pointer -DVALGRIND=1"
            address_sanitizer_cppflags="-DVALGRIND=1"
            address_sanitizer_ldflags="-Wc,-fsanitize=address"
      ])

undefined_sanitizer_cflags=
undefined_sanitizer_cppflags=
undefined_sanitizer_ldflags=
AC_ARG_ENABLE(undefined-sanitizer, AS_HELP_STRING([--enable-undefined-sanitizer], [enable -fsanitize=undefined]))
AS_IF([test "x$enable_undefined_sanitizer" = "xyes"], [
            CC_CHECK_FLAG_APPEND([with_us_cflags], [CFLAGS], [-fsanitize=undefined])
            AS_IF([test -z "$with_us_cflags"],
                  [AC_MSG_ERROR([*** -fsanitize=undefined is not supported])])
            undefined_sanitizer_cflags="$with_us_cflags -fno-omit-frame-pointer -DVALGRIND=1"
            undefined_sanitizer_cppflags="-DVALGRIND=1"
            undefined_sanitizer_ldflags="-Wc,-fsanitize=undefined"
      ])

sanitizer_cflags="$address_sanitizer_cflags $undefined_sanitizer_cflags"
sanitizer_cppflags="$address_sanitizer_cppflags $undefined_sanitizer_cppflags"
sanitizer_ldflags="$address_sanitizer_ldflags $undefined_sanitizer_ldflags"

CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
        -pipe \
        -Wall \
        -Wextra \
        -Wno-inline \
        -Wundef \
        "-Wformat=2 -Wformat-security -Wformat-nonliteral" \
        -Wlogical-op \
        -Wsign-compare \
        -Wmissing-include-dirs \
        -Wold-style-definition \
        -Wpointer-arith \
        -Winit-self \
        -Wdeclaration-after-statement \
        -Wfloat-equal \
        -Wsuggest-attribute=noreturn \
        -Wmissing-prototypes \
        -Wstrict-prototypes \
        -Wredundant-decls \
        -Wmissing-declarations \
        -Wmissing-noreturn \
        -Wshadow \
        -Wendif-labels \
        -Wstrict-aliasing=2 \
        -Wwrite-strings \
        -Wno-long-long \
        -Wno-overlength-strings \
        -Wno-unused-parameter \
        -Wno-missing-field-initializers \
        -Wno-unused-result \
        -Werror=overflow \
        -Wdate-time \
        -Wnested-externs \
        -ffast-math \
        -fno-common \
        -fdiagnostics-show-option \
        -fdiagnostics-color \
        -fno-strict-aliasing \
        -fvisibility=hidden \
        -ffunction-sections \
        -fdata-sections \
        -fstack-protector \
        -fstack-protector-strong \
        -fPIE \
        --param=ssp-buffer-size=4])
AS_CASE([$CFLAGS], [*-O[[12345\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
               -flto -ffat-lto-objects])],
        [AC_MSG_RESULT([skipping -flto, optimization not enabled])])
AC_SUBST([OUR_CFLAGS], "$with_cflags $sanitizer_cflags")

AS_CASE([$CFLAGS], [*-O[[12345\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cppflags], [CPPFLAGS], [\
               -Wp,-D_FORTIFY_SOURCE=2])],
        [AC_MSG_RESULT([skipping -D_FORTIFY_SOURCE, optimization not enabled])])
AC_SUBST([OUR_CPPFLAGS], "$with_cppflags $sanitizer_cppflags")

CC_CHECK_FLAGS_APPEND([with_ldflags], [LDFLAGS], [\
        -Wl,--as-needed \
        -Wl,--no-undefined \
        -Wl,--gc-sections \
        -Wl,-z,relro \
        -Wl,-z,now \
        -pie \
        -Wl,-fuse-ld=gold])
AC_SUBST([OUR_LDFLAGS], "$with_ldflags $sanitizer_ldflags")

AC_CHECK_SIZEOF(pid_t)
AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AC_CHECK_SIZEOF(time_t)
AC_CHECK_SIZEOF(rlim_t,,[
       #include <sys/time.h>
       #include <sys/resource.h>
])

# ------------------------------------------------------------------------------
# we use python to build the man page index, and for systemd-python
have_python=no
AC_ARG_WITH([python],
        [AS_HELP_STRING([--without-python], [Disable building the man page index and systemd-python (default: test)])])

have_lxml=no
AS_IF([test "x$with_python" != "xno"], [
        AM_PATH_PYTHON(,, [:])
        AS_IF([test "x$PYTHON" != "x:"], [
                AC_MSG_CHECKING([for python lxml module])
                AS_IF(["$PYTHON" -c 'import lxml' 2>/dev/null], [have_lxml=yes])
                AC_MSG_RESULT([$have_lxml])
                AS_IF([test "x$have_lxml" = "xyes"], [have_python=yes],
                      [AC_MSG_WARN([*** python support requires python-lxml module installed])])
        ])
])
AS_IF([test "$have_python" != "yes"], [
      AS_IF([test "$with_python" = "yes"],
            [AC_MSG_ERROR([*** python support requested but python support not found])])
      AS_IF([test "$with_python" != "no"],
            [AC_MSG_WARN([*** python support not found, some documentation cannot be built])])
])

AM_CONDITIONAL([HAVE_PYTHON], [test "x$have_python" = "xyes"])
AS_IF([test "x$PYTHON_BINARY" = "x"],
      [AS_IF([test "x$have_python" = "xyes"],
             [PYTHON_BINARY="$(which "$PYTHON")"],
             [PYTHON_BINARY=/usr/bin/python])])
AC_ARG_VAR(PYTHON_BINARY, [Python binary used to launch installed scripts])

AS_IF([test "x$have_python" != "xyes" -a "x$enable_python_devel" = "xyes"],
      [AC_MSG_ERROR([*** python-devel support requires --with-python])])

have_python_devel=no
AC_ARG_ENABLE(python_devel, AS_HELP_STRING([--disable-python-devel], [Do not build python modules]))
AS_IF([test "x$have_python" = "xyes" -a "x$enable_python_devel" != "xno"], [
      PKG_CHECK_MODULES([PYTHON_DEVEL], [python-${PYTHON_VERSION}],
            [have_python_devel=yes],
            [PKG_CHECK_MODULES([PYTHON_DEVEL], [python],
                  [have_python_devel=yes],
                  [have_python_devel=no])])
      AS_IF([test "x$have_python_devel" = xno -a "x$enable_python_devel" = xyes],
            [AC_MSG_ERROR([*** python-devel support requested but libraries not found])])
      AC_PATH_PROGS(SPHINX_BUILD, sphinx-build-${PYTHON_VERSION} sphinx-build)
])
AM_CONDITIONAL([HAVE_PYTHON_DEVEL], [test "$have_python_devel" = "yes"])

# ------------------------------------------------------------------------------

AC_SEARCH_LIBS([dlsym], [dl], [], [AC_MSG_ERROR([*** Dynamic linking loader library not found])])
AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])
AC_CHECK_HEADERS([linux/btrfs.h], [], [])

# unconditionally pull-in librt with old glibc versions
AC_SEARCH_LIBS([clock_gettime], [rt], [], [])

save_LIBS="$LIBS"
LIBS=
AC_SEARCH_LIBS([cap_init], [cap], [], [AC_MSG_ERROR([*** POSIX caps library not found])])
CAP_LIBS="$LIBS"
AC_SUBST(CAP_LIBS)

LIBS=
AC_SEARCH_LIBS([mq_open], [rt], [], [AC_MSG_ERROR([*** POSIX RT library not found])])
RT_LIBS="$LIBS"
AC_SUBST(RT_LIBS)
LIBS="$save_LIBS"

AC_CHECK_FUNCS([fanotify_init fanotify_mark])
AC_CHECK_FUNCS([__secure_getenv secure_getenv])
AC_CHECK_DECLS([gettid, pivot_root, name_to_handle_at, setns, LO_FLAGS_PARTSCAN],
               [], [], [[
#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/loop.h>
]])

AC_CHECK_DECLS([IFLA_PHYS_PORT_ID,
                IFLA_BOND_AD_INFO,
                IFLA_VLAN_PROTOCOL,
                IFLA_VXLAN_LOCAL6,
                IFLA_IPTUN_6RD_RELAY_PREFIXLEN,
                IFLA_BRIDGE_VLAN_INFO],
[], [], [[
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/if_link.h>
#include <linux/if_bridge.h>
]])

# This makes sure pkg.m4 is available.
m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

# ------------------------------------------------------------------------------
have_dbus=no
AC_ARG_ENABLE(dbus, AS_HELP_STRING([--disable-dbus], [disable usage of dbus-1 in tests]))
AS_IF([test "x$enable_dbus" != "xno"], [
        PKG_CHECK_MODULES(DBUS, [dbus-1 >= 1.3.2],
                [AC_DEFINE(HAVE_DBUS, 1, [Define if dbus-1 library is available]) have_dbus=yes],
                [have_dbus=no])
        AS_IF([test "x$have_dbus" = "xno" -a "x$enable_dbus" = "xyes"],
                [AC_MSG_ERROR([*** dbus-1 support requested but libraries not found])])])
AM_CONDITIONAL(HAVE_DBUS, [test "$have_dbus" = "yes"])

# ------------------------------------------------------------------------------
have_compat_libs=no
AC_ARG_ENABLE([compat_libs], AS_HELP_STRING([--enable-compat-libs],[Enable creation of compatibility libraries]),
                [case "${enableval}" in
                        yes) have_compat_libs=yes ;;
                        no) have_compat_libs=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --enable-compat-libs) ;;
                esac],
                [have_compat_libs=no])
AM_CONDITIONAL([ENABLE_COMPAT_LIBS], [test "$have_compat_libs" = "yes"])

# ------------------------------------------------------------------------------
have_coverage=no
AC_ARG_ENABLE(coverage, AS_HELP_STRING([--enable-coverage], [enable test coverage]))
if test "x$enable_coverage" = "xyes" ; then
        AC_CHECK_PROG(lcov_found, [lcov], [yes], [no])
        if test "x$lcov_found" = xno ; then
                AC_MSG_ERROR([*** lcov support requested but the program was not found])
        else
                lcov_version_major="`lcov --version | cut -d ' ' -f 4 | cut -d '.' -f 1`"
                lcov_version_minor="`lcov --version | cut -d ' ' -f 4 | cut -d '.' -f 2`"
                if test "$lcov_version_major" -eq 1 -a "$lcov_version_minor" -lt 10; then
                        AC_MSG_ERROR([*** lcov version is too old. 1.10 required])
                else
                        have_coverage=yes
                        CC_CHECK_FLAGS_APPEND([with_coverage_cflags], [CFLAGS], [\
                        -fprofile-arcs \
                        -ftest-coverage])
                        AC_SUBST([OUR_CFLAGS], "$with_cflags $with_coverage_cflags")
                fi
        fi
fi
AM_CONDITIONAL(ENABLE_COVERAGE, [test "$have_coverage" = "yes"])

# ------------------------------------------------------------------------------
have_kmod=no
AC_ARG_ENABLE(kmod, AS_HELP_STRING([--disable-kmod], [disable loadable modules support]))
if test "x$enable_kmod" != "xno"; then
        PKG_CHECK_EXISTS([ libkmod ], have_kmod=yes, have_kmod=no)
        if test "x$have_kmod" = "xyes"; then
                PKG_CHECK_MODULES(KMOD, [ libkmod >= 15 ],
                        [AC_DEFINE(HAVE_KMOD, 1, [Define if kmod is available])],
                        AC_MSG_ERROR([*** kmod version >= 15 not found]))
        fi
        if test "x$have_kmod" = xno -a "x$enable_kmod" = xyes; then
                AC_MSG_ERROR([*** kmod support requested, but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_KMOD, [test "$have_kmod" = "yes"])

# ------------------------------------------------------------------------------
have_blkid=no
AC_ARG_ENABLE(blkid, AS_HELP_STRING([--disable-blkid], [disable blkid support]))
if test "x$enable_blkid" != "xno"; then
        PKG_CHECK_MODULES(BLKID, [ blkid >= 2.20 ],
                [AC_DEFINE(HAVE_BLKID, 1, [Define if blkid is available]) have_blkid=yes], have_blkid=no)
        if test "x$have_blkid" = xno -a "x$enable_blkid" = xyes; then
                AC_MSG_ERROR([*** blkid support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_BLKID, [test "$have_blkid" = "yes"])

# ------------------------------------------------------------------------------
have_seccomp=no
AC_ARG_ENABLE(seccomp, AS_HELP_STRING([--disable-seccomp], [Disable optional SECCOMP support]))
if test "x$enable_seccomp" != "xno"; then
        PKG_CHECK_MODULES(SECCOMP, [libseccomp >= 1.0.0],
               [AC_DEFINE(HAVE_SECCOMP, 1, [Define if seccomp is available])
                have_seccomp=yes
                M4_DEFINES="$M4_DEFINES -DHAVE_SECCOMP"],
               [have_seccomp=no])
        if test "x$have_seccomp" = "xno" -a "x$enable_seccomp" = "xyes"; then
                AC_MSG_ERROR([*** seccomp support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_SECCOMP, [test "$have_seccomp" = "yes"])

# ------------------------------------------------------------------------------
have_ima=yes
AC_ARG_ENABLE([ima], AS_HELP_STRING([--disable-ima],[Disable optional IMA support]),
                [case "${enableval}" in
                        yes) have_ima=yes ;;
                        no) have_ima=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-ima) ;;
                esac],
                [have_ima=yes])

if test "x${have_ima}" != xno ; then
        AC_DEFINE(HAVE_IMA, 1, [Define if IMA is available])
fi

# ------------------------------------------------------------------------------
have_chkconfig=yes
AC_ARG_ENABLE([chkconfig], AS_HELP_STRING([--disable-chkconfig],[Disable optional chkconfig support]),
                [case "${enableval}" in
                        yes) have_chkconfig=yes ;;
                        no) have_chkconfig=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-chkconfig) ;;
                esac],
                [AC_PATH_PROG(CHKCONFIG, chkconfig)
                if test -z "$CHKCONFIG"; then
                        have_chkconfig=no
                else
                        have_chkconfig=yes
                fi])

if test "x${have_chkconfig}" != xno ; then
        AC_DEFINE(HAVE_CHKCONFIG, 1, [Define if CHKCONFIG is available])
fi

# ------------------------------------------------------------------------------
have_selinux=no
AC_ARG_ENABLE(selinux, AS_HELP_STRING([--disable-selinux], [Disable optional SELINUX support]))
if test "x$enable_selinux" != "xno"; then
        PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.1.9],
                [AC_DEFINE(HAVE_SELINUX, 1, [Define if SELinux is available])
                 have_selinux=yes
                 M4_DEFINES="$M4_DEFINES -DHAVE_SELINUX"],
                [have_selinux=no])
        if test "x$have_selinux" = xno -a "x$enable_selinux" = xyes; then
                AC_MSG_ERROR([*** SELinux support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_SELINUX, [test "$have_selinux" = "yes"])

have_apparmor=no
AC_ARG_ENABLE(apparmor, AS_HELP_STRING([--disable-apparmor], [Disable optional AppArmor support]))
if test "x$enable_apparmor" != "xno"; then
        PKG_CHECK_MODULES([APPARMOR], [libapparmor],
                [AC_DEFINE(HAVE_APPARMOR, 1, [Define if AppArmor is available])
                 have_apparmor=yes
                 M4_DEFINES="$M4_DEFINES -DHAVE_APPARMOR"],
                [have_apparmor=no])
        if test "x$have_apparmor" = xno -a "x$enable_apparmor" = xyes; then
                AC_MSG_ERROR([*** AppArmor support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_APPARMOR, [test "$have_apparmor" = "yes"])


AC_ARG_WITH(debug-shell,
        AS_HELP_STRING([--with-debug-shell=PATH],
                [Path to debug shell binary]),
        [SUSHELL="$withval"],[
        AS_IF([test "x${have_selinux}" != "xno"], [SUSHELL="/sbin/sushell"] , [SUSHELL="/bin/sh"])])

AC_SUBST(SUSHELL)

AC_ARG_WITH([debug-tty],
        AS_HELP_STRING([--with-debug-tty=PATH],
                [Specify the tty device for debug shell]),
        [DEBUGTTY="$withval"],
        [DEBUGTTY=/dev/tty9])

AC_SUBST(DEBUGTTY)

# ------------------------------------------------------------------------------
have_xz=no
AC_ARG_ENABLE(xz, AS_HELP_STRING([--disable-xz], [Disable optional XZ support]))
if test "x$enable_xz" != "xno"; then
        PKG_CHECK_MODULES(XZ, [ liblzma ],
                [AC_DEFINE(HAVE_XZ, 1, [Define if XZ is available]) have_xz=yes], have_xz=no)
        if test "x$have_xz" = xno -a "x$enable_xz" = xyes; then
                AC_MSG_ERROR([*** Xz support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_XZ, [test "$have_xz" = "yes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([pam],
        AS_HELP_STRING([--disable-pam],[Disable optional PAM support]),
                [case "${enableval}" in
                        yes) have_pam=yes ;;
                        no) have_pam=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-pam) ;;
                esac],
                [have_pam=auto])

if test "x${have_pam}" != xno ; then
        AC_CHECK_HEADERS(
                [security/pam_modules.h security/pam_modutil.h security/pam_ext.h],
                [have_pam=yes],
                [if test "x$have_pam" = xyes ; then
                        AC_MSG_ERROR([*** PAM headers not found.])
                fi])

        AC_CHECK_LIB(
                [pam],
                [pam_syslog],
                [have_pam=yes],
                [if test "x$have_pam" = xyes ; then
                        AC_MSG_ERROR([*** libpam not found.])
                fi])

        if test "x$have_pam" = xyes ; then
                PAM_LIBS="-lpam -lpam_misc"
                AC_DEFINE(HAVE_PAM, 1, [PAM available])
                M4_DEFINES="$M4_DEFINES -DHAVE_PAM"
        else
                have_pam=no
        fi
else
        PAM_LIBS=
fi
AC_SUBST(PAM_LIBS)
AM_CONDITIONAL([HAVE_PAM], [test "x$have_pam" != xno])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([acl],
        AS_HELP_STRING([--disable-acl],[Disable optional ACL support]),
                [case "${enableval}" in
                        yes) have_acl=yes ;;
                        no) have_acl=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-acl) ;;
                esac],
                [have_acl=auto])

if test "x${have_acl}" != xno ; then
        AC_CHECK_HEADERS(
                [sys/acl.h acl/libacl.h],
                [have_acl=yes],
                [if test "x$have_acl" = xyes ; then
                        AC_MSG_ERROR([*** ACL headers not found.])
                fi])

        AC_CHECK_LIB(
                [acl],
                [acl_get_file],
                [have_acl=yes],
                [if test "x$have_acl" = xyes ; then
                        AC_MSG_ERROR([*** libacl not found.])
                fi])

        if test "x$have_acl" = xyes ; then
                ACL_LIBS="-lacl"
                AC_DEFINE(HAVE_ACL, 1, [ACL available])
        else
                have_acl=no
        fi
else
        ACL_LIBS=
fi
AC_SUBST(ACL_LIBS)
AM_CONDITIONAL([HAVE_ACL], [test "x$have_acl" != xno])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([smack], AS_HELP_STRING([--disable-smack],[Disable optional SMACK support]),
                [case "${enableval}" in
                        yes) have_smack=yes ;;
                        no) have_smack=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-smack) ;;
                esac],
                [have_smack=auto])

if test "x${have_smack}" = xauto; then
        M4_DEFINES="$M4_DEFINES -DHAVE_SMACK"
        have_smack=yes
fi

AC_ARG_WITH(smack-run-label,
AS_HELP_STRING([--with-smack-run-label=STRING],
        [run systemd --system with a specific SMACK label]),
        [AC_DEFINE_UNQUOTED(SMACK_RUN_LABEL, ["$withval"], [Run with a smack label])],
        [])

if test "x${have_smack}" = xyes ; then
        AC_DEFINE(HAVE_SMACK, 1, [Define if SMACK is available])
fi

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([gcrypt],
        AS_HELP_STRING([--disable-gcrypt],[Disable optional GCRYPT support]),
                [case "${enableval}" in
                        yes) have_gcrypt=yes ;;
                        no) have_gcrypt=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-gcrypt) ;;
                esac],
                [have_gcrypt=auto])

if test "x${have_gcrypt}" != xno ; then
        AM_PATH_LIBGCRYPT(
                [1.4.5],
                [have_gcrypt=yes],
                [if test "x$have_gcrypt" = xyes ; then
                        AC_MSG_ERROR([*** GCRYPT headers not found.])
                fi])

        if test "x$have_gcrypt" = xyes ; then
                GCRYPT_LIBS="$LIBGCRYPT_LIBS"
                GCRYPT_CFLAGS="$LIBGCRYPT_CFLAGS"
                AC_DEFINE(HAVE_GCRYPT, 1, [GCRYPT available])
        else
                have_gcrypt=no
        fi
else
        GCRYPT_LIBS=
        GCRYPT_CFLAGS=
fi
AC_SUBST(GCRYPT_LIBS)
AC_SUBST(GCRYPT_CFLAGS)
AM_CONDITIONAL([HAVE_GCRYPT], [test "x$have_gcrypt" != xno])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([audit],
        AS_HELP_STRING([--disable-audit],[Disable optional AUDIT support]),
                [case "${enableval}" in
                        yes) have_audit=yes ;;
                        no) have_audit=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-audit) ;;
                esac],
                [have_audit=auto])

if test "x${have_audit}" != xno ; then
        AC_CHECK_HEADERS(
                [libaudit.h],
                [have_audit=yes],
                [if test "x$have_audit" = xyes ; then
                        AC_MSG_ERROR([*** AUDIT headers not found.])
                fi])

        AC_CHECK_LIB(
                [audit],
                [audit_open],
                [have_audit=yes],
                [if test "x$have_audit" = xyes ; then
                        AC_MSG_ERROR([*** libaudit not found.])
                fi])

        if test "x$have_audit" = xyes ; then
                AUDIT_LIBS="-laudit"
                AC_DEFINE(HAVE_AUDIT, 1, [AUDIT available])
        else
                have_audit=no
        fi
else
        AUDIT_LIBS=
fi
AC_SUBST(AUDIT_LIBS)

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([elfutils],
        AS_HELP_STRING([--disable-elfutils],[Disable optional ELFUTILS support]),
                [case "${enableval}" in
                        yes) have_elfutils=yes ;;
                        no) have_elfutils=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-elfutils) ;;
                esac],
                [have_elfutils=auto])

if test "x${have_elfutils}" != xno ; then
        AC_CHECK_HEADERS(
                [elfutils/libdwfl.h],
                [],
                [if test "x$have_elfutils" = xyes ; then
                        AC_MSG_ERROR([*** ELFUTILS headers not found.])
                fi])

        AC_CHECK_LIB(
                [dw],
                [dwfl_begin],
                [],
                [if test "x$have_elfutils" = xyes ; then
                        AC_MSG_ERROR([*** ELFUTILS libs not found.])
                fi])

        AC_CHECK_LIB(
                [dw],
                [dwfl_core_file_attach],
                [have_elfutils=yes],
                [if test "x$have_elfutils" = xyes ; then
                        AC_MSG_ERROR([*** ELFUTILS >= 158 is required.])
                fi])

        if test "x$have_elfutils" = xyes ; then
                ELFUTILS_LIBS="-lelf -ldw"
                AC_DEFINE(HAVE_ELFUTILS, 1, [ELFUTILS available])
        else
                have_elfutils=no
        fi
else
        ELFUTILS_LIBS=
fi
AC_SUBST(ELFUTILS_LIBS)
AM_CONDITIONAL(HAVE_ELFUTILS, [test "$have_elfutils" = "yes"])

# ------------------------------------------------------------------------------
have_libcryptsetup=no
AC_ARG_ENABLE(libcryptsetup, AS_HELP_STRING([--disable-libcryptsetup], [disable libcryptsetup tools]))
if test "x$enable_libcryptsetup" != "xno"; then
        PKG_CHECK_MODULES(LIBCRYPTSETUP, [ libcryptsetup >= 1.6.0 ],
                [AC_DEFINE(HAVE_LIBCRYPTSETUP, 1, [Define if libcryptsetup is available]) have_libcryptsetup=yes], have_libcryptsetup=no)
        if test "x$have_libcryptsetup" = xno -a "x$enable_libcryptsetup" = xyes; then
                AC_MSG_ERROR([*** libcryptsetup support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_LIBCRYPTSETUP, [test "$have_libcryptsetup" = "yes"])

# ------------------------------------------------------------------------------
have_qrencode=no
AC_ARG_ENABLE(qrencode, AS_HELP_STRING([--disable-qrencode], [disable qrencode support]))
if test "x$enable_qrencode" != "xno"; then
        PKG_CHECK_MODULES(QRENCODE, [ libqrencode ],
                [AC_DEFINE(HAVE_QRENCODE, 1, [Define if qrencode is available]) have_qrencode=yes], have_qrencode=no)
        if test "x$have_qrencode" = xno -a "x$enable_qrencode" = xyes; then
                AC_MSG_ERROR([*** qrencode support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_QRENCODE, [test "$have_qrencode" = "yes"])

# ------------------------------------------------------------------------------
have_microhttpd=no
AC_ARG_ENABLE(microhttpd, AS_HELP_STRING([--disable-microhttpd], [disable microhttpd support]))
if test "x$enable_microhttpd" != "xno"; then
        PKG_CHECK_MODULES(MICROHTTPD, [libmicrohttpd >= 0.9.33],
                [AC_DEFINE(HAVE_MICROHTTPD, 1, [Define if microhttpd is available]) have_microhttpd=yes], have_microhttpd=no)
        if test "x$have_microhttpd" = xno -a "x$enable_microhttpd" = xyes; then
                AC_MSG_ERROR([*** microhttpd support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_MICROHTTPD, [test "$have_microhttpd" = "yes"])

# ------------------------------------------------------------------------------
have_gnutls=no
AC_ARG_ENABLE(gnutls, AS_HELP_STRING([--disable-gnutls], [disable gnutls support]))
if test "x$enable_gnutls" != "xno"; then
        PKG_CHECK_MODULES(GNUTLS, [gnutls >= 3.1.4],
                [AC_DEFINE(HAVE_GNUTLS, 1, [Define if gnutls is available]) have_gnutls=yes], have_gnutls=no)
        if test "x$have_gnutls" = xno -a "x$enable_gnutls" = xyes; then
                AC_MSG_ERROR([*** gnutls support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_GNUTLS, [test "$have_gnutls" = "yes"])

# ------------------------------------------------------------------------------
have_binfmt=no
AC_ARG_ENABLE(binfmt, AS_HELP_STRING([--disable-binfmt], [disable binfmt tool]))
if test "x$enable_binfmt" != "xno"; then
        have_binfmt=yes
fi
AM_CONDITIONAL(ENABLE_BINFMT, [test "$have_binfmt" = "yes"])

# ------------------------------------------------------------------------------
have_vconsole=no
AC_ARG_ENABLE(vconsole, AS_HELP_STRING([--disable-vconsole], [disable vconsole tool]))
if test "x$enable_vconsole" != "xno"; then
        have_vconsole=yes
fi
AM_CONDITIONAL(ENABLE_VCONSOLE, [test "$have_vconsole" = "yes"])

# ------------------------------------------------------------------------------
have_readahead=no
AC_ARG_ENABLE(readahead, AS_HELP_STRING([--disable-readahead], [disable readahead tools]))
if test "x$enable_readahead" != "xno"; then
        have_readahead=yes
fi
AM_CONDITIONAL(ENABLE_READAHEAD, [test "$have_readahead" = "yes"])

# ------------------------------------------------------------------------------
have_bootchart=no
AC_ARG_ENABLE(bootchart, AS_HELP_STRING([--disable-bootchart], [disable bootchart tool]))
if test "x$enable_bootchart" != "xno"; then
        have_bootchart=yes
fi
AM_CONDITIONAL(ENABLE_BOOTCHART, [test "$have_bootchart" = "yes"])

# ------------------------------------------------------------------------------
have_quotacheck=no
AC_ARG_ENABLE(quotacheck, AS_HELP_STRING([--disable-quotacheck], [disable quotacheck tools]))
if test "x$enable_quotacheck" != "xno"; then
        have_quotacheck=yes
fi
AM_CONDITIONAL(ENABLE_QUOTACHECK, [test "$have_quotacheck" = "yes"])

# ------------------------------------------------------------------------------
have_tmpfiles=no
AC_ARG_ENABLE(tmpfiles, AS_HELP_STRING([--disable-tmpfiles], [disable tmpfiles support]))
if test "x$enable_tmpfiles" != "xno"; then
        have_tmpfiles=yes
fi
AM_CONDITIONAL(ENABLE_TMPFILES, [test "$have_tmpfiles" = "yes"])

# ------------------------------------------------------------------------------
have_sysusers=no
AC_ARG_ENABLE(sysusers, AS_HELP_STRING([--disable-sysusers], [disable sysusers support]))
if test "x$enable_sysusers" != "xno"; then
        have_sysusers=yes
fi
AM_CONDITIONAL(ENABLE_SYSUSERS, [test "$have_sysusers" = "yes"])

# ------------------------------------------------------------------------------
have_randomseed=no
AC_ARG_ENABLE(randomseed, AS_HELP_STRING([--disable-randomseed], [disable randomseed tools]))
if test "x$enable_randomseed" != "xno"; then
        have_randomseed=yes
fi
AM_CONDITIONAL(ENABLE_RANDOMSEED, [test "$have_randomseed" = "yes"])

# ------------------------------------------------------------------------------
have_backlight=no
AC_ARG_ENABLE(backlight, AS_HELP_STRING([--disable-backlight], [disable backlight tools]))
if test "x$enable_backlight" != "xno"; then
        have_backlight=yes
fi
AM_CONDITIONAL(ENABLE_BACKLIGHT, [test "$have_backlight" = "yes"])

# ------------------------------------------------------------------------------
have_rfkill=no
AC_ARG_ENABLE(rfkill, AS_HELP_STRING([--disable-rfkill], [disable rfkill tools]))
if test "x$enable_rfkill" != "xno"; then
        have_rfkill=yes
fi
AM_CONDITIONAL(ENABLE_RFKILL, [test "$have_rfkill" = "yes"])

# ------------------------------------------------------------------------------
have_logind=no
AC_ARG_ENABLE(logind, AS_HELP_STRING([--disable-logind], [disable login daemon]))
if test "x$enable_logind" != "xno"; then
        have_logind=yes
fi
AM_CONDITIONAL(ENABLE_LOGIND, [test "$have_logind" = "yes"])
AS_IF([test "$have_logind" = "yes"], [ AC_DEFINE(HAVE_LOGIND, [1], [Logind support available]) ])

# ------------------------------------------------------------------------------
have_machined=no
AC_ARG_ENABLE(machined, AS_HELP_STRING([--disable-machined], [disable machine daemon]))
if test "x$enable_machined" != "xno"; then
        have_machined=yes
fi
AM_CONDITIONAL(ENABLE_MACHINED, [test "$have_machined" = "yes"])
AS_IF([test "$have_machined" = "yes"], [ AC_DEFINE(HAVE_MACHINED, [1], [Machined support available]) ])

# ------------------------------------------------------------------------------
have_hostnamed=no
AC_ARG_ENABLE(hostnamed, AS_HELP_STRING([--disable-hostnamed], [disable hostname daemon]))
if test "x$enable_hostnamed" != "xno"; then
        have_hostnamed=yes
fi
AM_CONDITIONAL(ENABLE_HOSTNAMED, [test "$have_hostnamed" = "yes"])

# ------------------------------------------------------------------------------
have_timedated=no
AC_ARG_ENABLE(timedated, AS_HELP_STRING([--disable-timedated], [disable timedate daemon]))
if test "x$enable_timedated" != "xno"; then
        have_timedated=yes
fi
AM_CONDITIONAL(ENABLE_TIMEDATED, [test "$have_timedated" = "yes"])

# ------------------------------------------------------------------------------
have_timesyncd=no
AC_ARG_ENABLE(timesyncd, AS_HELP_STRING([--disable-timesyncd], [disable timesync daemon]))
if test "x$enable_timesyncd" != "xno"; then
        have_timesyncd=yes
fi
AM_CONDITIONAL(ENABLE_TIMESYNCD, [test "$have_timesyncd" = "yes"])

AC_ARG_WITH(ntp-servers,
        AS_HELP_STRING([--with-ntp-servers=NTPSERVERS],
                [Space-separated list of default NTP servers]),
        [NTP_SERVERS="$withval"],
        [NTP_SERVERS="time1.google.com time2.google.com time3.google.com time4.google.com"])

AC_DEFINE_UNQUOTED(NTP_SERVERS, ["$NTP_SERVERS"], [Default NTP Servers])
AC_SUBST(NTP_SERVERS)

AC_ARG_WITH(time-epoch,
        AS_HELP_STRING([--with-time-epoch=SECONDS],
                [Time epoch for time clients]),
        [TIME_EPOCH="$withval"],
        [TIME_EPOCH="`stat -c %Y ${srcdir}/NEWS 2>/dev/null || echo 0`"])

AC_DEFINE_UNQUOTED(TIME_EPOCH, [$TIME_EPOCH], [Time Epoch])

# ------------------------------------------------------------------------------
AC_ARG_WITH(system-uid-max,
        AS_HELP_STRING([--with-system-uid-max=UID]
                [Maximum UID for system users]),
        [SYSTEM_UID_MAX="$withval"],
        [SYSTEM_UID_MAX="`awk 'BEGIN { uid=999 } /^\s*SYS_UID_MAX\s+/ { uid=$2 } END { print uid }' /etc/login.defs 2>/dev/null || echo 999`"])

AC_DEFINE_UNQUOTED(SYSTEM_UID_MAX, [$SYSTEM_UID_MAX], [Maximum System UID])
AC_SUBST(SYSTEM_UID_MAX)

# ------------------------------------------------------------------------------
AC_ARG_WITH(system-gid-max,
        AS_HELP_STRING([--with-system-gid-max=GID]
                [Maximum GID for system groups]),
        [SYSTEM_GID_MAX="$withval"],
        [SYSTEM_GID_MAX="`awk 'BEGIN { gid=999 } /^\s*SYS_GID_MAX\s+/ { gid=$2 } END { print gid }' /etc/login.defs 2>/dev/null || echo 999`"])

AC_DEFINE_UNQUOTED(SYSTEM_GID_MAX, [$SYSTEM_GID_MAX], [Maximum System GID])
AC_SUBST(SYSTEM_GID_MAX)

# ------------------------------------------------------------------------------
have_localed=no
AC_ARG_ENABLE(localed, AS_HELP_STRING([--disable-localed], [disable locale daemon]))
if test "x$enable_localed" != "xno"; then
        have_localed=yes
fi
AM_CONDITIONAL(ENABLE_LOCALED, [test "$have_localed" = "yes"])

# ------------------------------------------------------------------------------
have_coredump=no
AC_ARG_ENABLE(coredump, AS_HELP_STRING([--disable-coredump], [disable coredump hook]))
if test "x$enable_coredump" != "xno"; then
        have_coredump=yes
fi
AM_CONDITIONAL(ENABLE_COREDUMP, [test "$have_coredump" = "yes"])

# ------------------------------------------------------------------------------
have_polkit=no
AC_ARG_ENABLE(polkit, AS_HELP_STRING([--disable-polkit], [disable PolicyKit support]))
if test "x$enable_polkit" != "xno"; then
        AC_DEFINE(ENABLE_POLKIT, 1, [Define if PolicyKit support is to be enabled])
        have_polkit=yes
fi
AM_CONDITIONAL(ENABLE_POLKIT, [test "x$have_polkit" = "xyes"])

# ------------------------------------------------------------------------------
have_resolved=no
AC_ARG_ENABLE(resolved, AS_HELP_STRING([--disable-resolved], [disable resolve daemon]))
if test "x$enable_resolved" != "xno"; then
        have_resolved=yes
fi
AM_CONDITIONAL(ENABLE_RESOLVED, [test "$have_resolved" = "yes"])

AC_ARG_WITH(dns-servers,
        AS_HELP_STRING([--with-dns-servers=DNSSERVERS],
                [Space-separated list of default DNS servers]),
        [DNS_SERVERS="$withval"],
        [DNS_SERVERS="8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844"])

AC_DEFINE_UNQUOTED(DNS_SERVERS, ["$DNS_SERVERS"], [Default DNS Servers])
AC_SUBST(DNS_SERVERS)

# ------------------------------------------------------------------------------
have_networkd=no
AC_ARG_ENABLE(networkd, AS_HELP_STRING([--disable-networkd], [disable networkd]))
AS_IF([test "x$enable_networkd" != "xno"], [
        AC_DEFINE(ENABLE_NETWORKD, 1, [Define if networkd support is to be enabled])
        have_networkd=yes
])
AM_CONDITIONAL(ENABLE_NETWORKD, [test "x$have_networkd" = "xyes"])

# ------------------------------------------------------------------------------
have_efi=no
AC_ARG_ENABLE(efi, AS_HELP_STRING([--disable-efi], [disable EFI support]))
if test "x$enable_efi" != "xno"; then
        AC_DEFINE(ENABLE_EFI, 1, [Define if EFI support is to be enabled])
        have_efi=yes
fi
AM_CONDITIONAL(ENABLE_EFI, [test "x$have_efi" = "xyes"])

# ------------------------------------------------------------------------------
have_multi_seat_x=no
AC_ARG_ENABLE(multi_seat_x, AS_HELP_STRING([--disable-multi-seat-x], [do not build multi-seat-x]))
if test "x$enable_multi_seat_x" != "xno"; then
        have_multi_seat_x=yes
fi
AM_CONDITIONAL(ENABLE_MULTI_SEAT_X, [test "$have_multi_seat_x" = "yes"])

# ------------------------------------------------------------------------------
have_kdbus=no
AC_ARG_ENABLE(kdbus, AS_HELP_STRING([--enable-kdbus], [do connect to kdbus by default]))
if test "x$enable_kdbus" = "xyes"; then
        AC_DEFINE(ENABLE_KDBUS, 1, [Define if kdbus support is to be enabled])
        have_kdbus=yes
        M4_DEFINES="$M4_DEFINES -DENABLE_KDBUS"
fi
AM_CONDITIONAL(ENABLE_KDBUS, [test "$have_kdbus" = "yes"])

# ------------------------------------------------------------------------------
AC_ARG_WITH(rc-local-script-path-start,
        AS_HELP_STRING([--with-rc-local-script-path-start=PATH],
                [Path to /etc/rc.local]),
        [RC_LOCAL_SCRIPT_PATH_START="$withval"],
        [RC_LOCAL_SCRIPT_PATH_START="/etc/rc.local"])

AC_ARG_WITH(rc-local-script-path-stop,
        AS_HELP_STRING([--with-rc-local-script-path-stop=PATH],
                [Path to /usr/sbin/halt.local]),
        [RC_LOCAL_SCRIPT_PATH_STOP="$withval"],
        [RC_LOCAL_SCRIPT_PATH_STOP="/usr/sbin/halt.local"])

AC_DEFINE_UNQUOTED(RC_LOCAL_SCRIPT_PATH_START, ["$RC_LOCAL_SCRIPT_PATH_START"], [Path of /etc/rc.local script])
AC_DEFINE_UNQUOTED(RC_LOCAL_SCRIPT_PATH_STOP, ["$RC_LOCAL_SCRIPT_PATH_STOP"], [Path of /usr/sbin/halt.local script])

AC_SUBST(RC_LOCAL_SCRIPT_PATH_START)
AC_SUBST(RC_LOCAL_SCRIPT_PATH_STOP)

# ------------------------------------------------------------------------------
AC_ARG_WITH(kbd-loadkeys,
        AS_HELP_STRING([--with-kbd-loadkeys=PATH],
                [Path to loadkeys]),
        [KBD_LOADKEYS="$withval"],
        [KBD_LOADKEYS="/usr/bin/loadkeys"])

AC_ARG_WITH(kbd-setfont,
        AS_HELP_STRING([--with-kbd-setfont=PATH],
                [Path to setfont]),
        [KBD_SETFONT="$withval"],
        [KBD_SETFONT="/usr/bin/setfont"])

AC_DEFINE_UNQUOTED(KBD_LOADKEYS, ["$KBD_LOADKEYS"], [Path of loadkeys])
AC_DEFINE_UNQUOTED(KBD_SETFONT, ["$KBD_SETFONT"], [Path of setfont])

AC_SUBST(KBD_LOADKEYS)
AC_SUBST(KBD_SETFONT)

AC_ARG_WITH(telinit,
        AS_HELP_STRING([--with-telinit=PATH],
                [Path to telinit]),
        [TELINIT="$withval"],
        [TELINIT="/lib/sysvinit/telinit"])

AC_DEFINE_UNQUOTED(TELINIT, ["$TELINIT"], [Path to telinit])

AC_SUBST(TELINIT)

AC_CHECK_HEADERS_ONCE([valgrind/memcheck.h valgrind/valgrind.h])

# ------------------------------------------------------------------------------
have_myhostname=no
AC_ARG_ENABLE(myhostname, AS_HELP_STRING([--disable-myhostname], [disable nss-myhostname support]))
if test "x$enable_myhostname" != "xno"; then
        AC_HEADER_STDC
        AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h nss.h sys/ioctl.h sys/auxv.h])

        AC_C_CONST
        AC_TYPE_SIZE_T
        AC_HEADER_TIME

        AC_FUNC_MALLOC
        AC_FUNC_SELECT_ARGTYPES
        AC_CHECK_FUNCS([gethostbyaddr gethostbyname gettimeofday inet_ntoa memset select socket strcspn strdup strerror strncasecmp strcasecmp strspn])

        have_myhostname=yes
fi
AM_CONDITIONAL(HAVE_MYHOSTNAME, [test "$have_myhostname" = "yes"])

# ------------------------------------------------------------------------------
AC_ARG_WITH(firmware-path,
       AS_HELP_STRING([--with-firmware-path=DIR[[[:DIR[...]]]]],
          [Firmware search path (default="")]),
       [], [with_firmware_path=""])
OLD_IFS=$IFS
IFS=:
for i in $with_firmware_path; do
       if test "x${FIRMWARE_PATH}" = "x"; then
              FIRMWARE_PATH="\\\"${i}/\\\""
       else
              FIRMWARE_PATH="${FIRMWARE_PATH}, \\\"${i}/\\\""
       fi
done
IFS=$OLD_IFS
AC_SUBST(FIRMWARE_PATH)
AS_IF([test "x${FIRMWARE_PATH}" != "x"], [ AC_DEFINE(HAVE_FIRMWARE, 1, [Define if FIRMWARE is available]) ])
AM_CONDITIONAL(ENABLE_FIRMWARE, [test "x${FIRMWARE_PATH}" != "x"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE([gudev],
       AS_HELP_STRING([--disable-gudev], [disable Gobject libudev support @<:@default=enabled@:>@]),
       [], [enable_gudev=yes])
AS_IF([test "x$enable_gudev" = "xyes"], [ PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.22.0 gobject-2.0 >= 2.22.0 gio-2.0]) ])
AM_CONDITIONAL([ENABLE_GUDEV], [test "x$enable_gudev" = "xyes"])
AS_IF([test "x$enable_gudev" = "xyes"], [ AC_DEFINE(HAVE_GLIB, 1, [Define if glib is available]) ])

# ------------------------------------------------------------------------------
have_manpages=no
AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages], [disable manpages]))
AS_IF([test "x$enable_manpages" != xno], [have_manpages=yes])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$have_manpages" = "xyes"])

# ------------------------------------------------------------------------------

# Location of the init scripts as mandated by LSB
SYSTEM_SYSVINIT_PATH=/etc/init.d
SYSTEM_SYSVRCND_PATH=/etc/rc.d

AC_ARG_WITH([sysvinit-path],
        [AS_HELP_STRING([--with-sysvinit-path=PATH],
                [Specify the path to where the SysV init scripts are located])],
        [SYSTEM_SYSVINIT_PATH="$withval"],
        [])

AC_ARG_WITH([sysvrcnd-path],
        [AS_HELP_STRING([--with-sysvrcnd-path=PATH],
                [Specify the path to the base directory for the SysV rcN.d directories])],
        [SYSTEM_SYSVRCND_PATH="$withval"],
        [])

if test "x${SYSTEM_SYSVINIT_PATH}" != "x" -a "x${SYSTEM_SYSVRCND_PATH}" != "x"; then
        AC_DEFINE(HAVE_SYSV_COMPAT, [], [SysV init scripts and rcN.d links are supported.])
        SYSTEM_SYSV_COMPAT="yes"
        M4_DEFINES="$M4_DEFINES -DHAVE_SYSV_COMPAT"
elif test "x${SYSTEM_SYSVINIT_PATH}" != "x" -o "x${SYSTEM_SYSVRCND_PATH}" != "x"; then
        AC_MSG_ERROR([*** You need both --with-sysvinit-path=PATH and --with-sysvrcnd-path=PATH to enable SysV compatibility support, or both empty to disable it.])
else
        SYSTEM_SYSV_COMPAT="no"
fi

AC_SUBST(SYSTEM_SYSVINIT_PATH)
AC_SUBST(SYSTEM_SYSVRCND_PATH)
AC_SUBST(M4_DEFINES)

AM_CONDITIONAL(HAVE_SYSV_COMPAT, test "$SYSTEM_SYSV_COMPAT" = "yes")

AC_ARG_WITH([tty-gid],
        [AS_HELP_STRING([--with-tty-gid=GID],
                [Specify the numeric GID of the 'tty' group])],
        [TTY_GID="$withval"],
        [TTY_GID="5"])

AC_DEFINE_UNQUOTED(TTY_GID, [$TTY_GID], [GID of the 'tty' group])
AC_SUBST(TTY_GID)

AC_ARG_WITH([dbuspolicydir],
        AS_HELP_STRING([--with-dbuspolicydir=DIR], [D-Bus policy directory]),
        [],
        [with_dbuspolicydir=$($PKG_CONFIG --variable=sysconfdir dbus-1)/dbus-1/system.d])

AC_ARG_WITH([dbussessionservicedir],
        AS_HELP_STRING([--with-dbussessionservicedir=DIR], [D-Bus session service directory]),
        [],
        [with_dbussessionservicedir=$($PKG_CONFIG --variable=session_bus_services_dir dbus-1)])

AC_ARG_WITH([dbussystemservicedir],
        AS_HELP_STRING([--with-dbussystemservicedir=DIR], [D-Bus system service directory]),
        [],
        [with_dbussystemservicedir=$(readlink -m $($PKG_CONFIG --variable=session_bus_services_dir dbus-1)/../system-services)])

AC_ARG_WITH([dbusinterfacedir],
        AS_HELP_STRING([--with-dbusinterfacedir=DIR], [D-Bus interface directory]),
        [],
        [with_dbusinterfacedir=$(readlink -m $($PKG_CONFIG --variable=session_bus_services_dir dbus-1)/../interfaces)])

AC_ARG_WITH([bashcompletiondir],
        AS_HELP_STRING([--with-bashcompletiondir=DIR], [Bash completions directory]),
        [],
        [AS_IF([$($PKG_CONFIG --exists bash-completion)], [
                with_bashcompletiondir=$($PKG_CONFIG --variable=completionsdir bash-completion)
        ] , [
                with_bashcompletiondir=${datadir}/bash-completion/completions
        ])])

AC_ARG_WITH([zshcompletiondir],
        AS_HELP_STRING([--with-zshcompletiondir=DIR], [Zsh completions directory]),
        [], [with_zshcompletiondir=${datadir}/zsh/site-functions])

AC_ARG_WITH([rootprefix],
        AS_HELP_STRING([--with-rootprefix=DIR], [rootfs directory prefix for config files and kernel modules]),
        [], [with_rootprefix=${ac_default_prefix}])

AC_ARG_WITH([rootlibdir],
        AS_HELP_STRING([--with-rootlibdir=DIR], [Root directory for libraries necessary for boot]),
        [],
        [with_rootlibdir=${libdir}])

AC_ARG_WITH([pamlibdir],
        AS_HELP_STRING([--with-pamlibdir=DIR], [Directory for PAM modules]),
        [],
        [with_pamlibdir=${with_rootlibdir}/security])

AC_ARG_WITH([pamconfdir],
        AS_HELP_STRING([--with-pamconfdir=DIR], [Directory for PAM configuration]),
        [],
        [with_pamconfdir=${sysconfdir}/pam.d])

AC_ARG_ENABLE([split-usr],
        AS_HELP_STRING([--enable-split-usr], [Assume that /bin, /sbin aren\'t symlinks into /usr]),
        [],
        [AS_IF([test "x${ac_default_prefix}" != "x${with_rootprefix}"], [
                enable_split_usr=yes
        ], [
                enable_split_usr=no
        ])])

AS_IF([test "x${enable_split_usr}" = "xyes"], [
        AC_DEFINE(HAVE_SPLIT_USR, 1, [Define if /bin, /sbin aren't symlinks into /usr])
])

# Work around intltoolize and gtk-doc problems in VPATH builds
AM_CONDITIONAL([ENABLE_GTK_DOC_TESTS], [test "x$0" = "x./configure"],
                                       [Define to do gtk-doc tests])
AS_IF([test "x$0" != "x./configure"], [
        AC_SUBST([INTLTOOL_UPDATE], [/bin/true])
])

AC_ARG_ENABLE(tests,
       [AC_HELP_STRING([--disable-tests], [disable tests])],
       enable_tests=$enableval, enable_tests=yes)
AM_CONDITIONAL(ENABLE_TESTS, [test x$enable_tests = xyes])

AC_SUBST([dbuspolicydir], [$with_dbuspolicydir])
AC_SUBST([dbussessionservicedir], [$with_dbussessionservicedir])
AC_SUBST([dbussystemservicedir], [$with_dbussystemservicedir])
AC_SUBST([dbusinterfacedir], [$with_dbusinterfacedir])
AC_SUBST([bashcompletiondir], [$with_bashcompletiondir])
AC_SUBST([zshcompletiondir], [$with_zshcompletiondir])
AC_SUBST([pamlibdir], [$with_pamlibdir])
AC_SUBST([pamconfdir], [$with_pamconfdir])
AC_SUBST([rootprefix], [$with_rootprefix])
AC_SUBST([rootlibdir], [$with_rootlibdir])

AC_CONFIG_FILES([
        Makefile po/Makefile.in
        docs/libudev/Makefile
        docs/libudev/version.xml
        docs/gudev/Makefile
        docs/gudev/version.xml
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE_NAME $VERSION

        libcryptsetup:           ${have_libcryptsetup}
        PAM:                     ${have_pam}
        AUDIT:                   ${have_audit}
        IMA:                     ${have_ima}
        AppArmor:                ${have_apparmor}
        SELinux:                 ${have_selinux}
        SECCOMP:                 ${have_seccomp}
        SMACK:                   ${have_smack}
        XZ:                      ${have_xz}
        ACL:                     ${have_acl}
        GCRYPT:                  ${have_gcrypt}
        QRENCODE:                ${have_qrencode}
        MICROHTTPD:              ${have_microhttpd}
        CHKCONFIG:               ${have_chkconfig}
        GNUTLS:                  ${have_gnutls}
        ELFUTILS:                ${have_elfutils}
        binfmt:                  ${have_binfmt}
        vconsole:                ${have_vconsole}
        readahead:               ${have_readahead}
        bootchart:               ${have_bootchart}
        quotacheck:              ${have_quotacheck}
        tmpfiles:                ${have_tmpfiles}
        sysusers:                ${have_sysusers}
        randomseed:              ${have_randomseed}
        backlight:               ${have_backlight}
        rfkill:                  ${have_rfkill}
        logind:                  ${have_logind}
        machined:                ${have_machined}
        hostnamed:               ${have_hostnamed}
        timedated:               ${have_timedated}
        timesyncd:               ${have_timesyncd}
        default NTP servers:     ${NTP_SERVERS}
        time epoch:              ${TIME_EPOCH}
        localed:                 ${have_localed}
        networkd:                ${have_networkd}
        resolved:                ${have_resolved}
        default DNS servers:     ${DNS_SERVERS}
        coredump:                ${have_coredump}
        polkit:                  ${have_polkit}
        efi:                     ${have_efi}
        kmod:                    ${have_kmod}
        blkid:                   ${have_blkid}
        dbus:                    ${have_dbus}
        nss-myhostname:          ${have_myhostname}
        gudev:                   ${enable_gudev}
        gintrospection:          ${enable_introspection}
        multi-seat-x:            ${have_multi_seat_x}
        kdbus:                   ${have_kdbus}
        Python:                  ${have_python}
        Python Headers:          ${have_python_devel}
        man pages:               ${have_manpages}
        gtk-doc:                 ${enable_gtk_doc}
        test coverage:           ${have_coverage}
        Split /usr:              ${enable_split_usr}
        SysV compatibility:      ${SYSTEM_SYSV_COMPAT}
        compatibility libraries: ${have_compat_libs}

        prefix:                  ${prefix}
        rootprefix:              ${with_rootprefix}
        sysconf dir:             ${sysconfdir}
        datarootdir:             ${datarootdir}
        includedir:              ${includedir}
        include_prefix:          ${INCLUDE_PREFIX}
        lib dir:                 ${libdir}
        rootlib dir:             ${with_rootlibdir}
        SysV init scripts:       ${SYSTEM_SYSVINIT_PATH}
        SysV rc?.d directories:  ${SYSTEM_SYSVRCND_PATH}
        Build Python:            ${PYTHON}
        Installation Python:     ${PYTHON_BINARY}
        sphinx binary:           ${SPHINX_BUILD}
        firmware path:           ${FIRMWARE_PATH}
        PAM modules dir:         ${with_pamlibdir}
        PAM configuration dir:   ${with_pamconfdir}
        D-Bus policy dir:        ${with_dbuspolicydir}
        D-Bus session dir:       ${with_dbussessionservicedir}
        D-Bus system dir:        ${with_dbussystemservicedir}
        D-Bus interfaces dir:    ${with_dbusinterfacedir}
        Bash completions dir:    ${with_bashcompletiondir}
        Zsh completions dir:     ${with_zshcompletiondir}
        Extra start script:      ${RC_LOCAL_SCRIPT_PATH_START}
        Extra stop script:       ${RC_LOCAL_SCRIPT_PATH_STOP}
        Debug shell:             ${SUSHELL} @ ${DEBUGTTY}
        TTY GID:                 ${TTY_GID}
        Maximum System UID:      ${SYSTEM_UID_MAX}
        Maximum System GID:      ${SYSTEM_GID_MAX}

        CFLAGS:                  ${OUR_CFLAGS} ${CFLAGS}
        CPPFLAGS:                ${OUR_CPPFLAGS} ${CPPFLAGS}
        LDFLAGS:                 ${OUR_LDFLAGS} ${LDFLAGS}
        PYTHON_CFLAGS:           ${PYTHON_DEVEL_CFLAGS}
        PYTHON_LIBS:             ${PYTHON_DEVEL_LIBS}
])
