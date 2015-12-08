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
        [228],
        [http://github.com/systemd/systemd/issues],
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
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects parallel-tests])
AM_SILENT_RULES([yes])
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], "$host", [Canonical host string.])

AC_PROG_CC_C99

AX_COMPILER_VENDOR
AS_IF([test "x$ax_cv_c_compiler_vendor" = "xgnu"], [
      AC_CHECK_TOOLS([AR], [gcc-ar ar], [:])
      AC_CHECK_TOOLS([NM], [gcc-nm nm], [:])
      AC_CHECK_TOOLS([RANLIB], [gcc-ranlib ranlib], [:])
])

LT_PREREQ(2.2)
LT_INIT([disable-static])

AS_IF([test "x$enable_static" = "xyes"], [AC_MSG_ERROR([--enable-static is not supported by systemd])])
AS_IF([test "x$enable_largefile" = "xno"], [AC_MSG_ERROR([--disable-largefile is not supported by systemd])])

SET_ARCH(X86_64, x86_64*)
SET_ARCH(IA32, i*86*)
SET_ARCH(MIPS, mips*)
SET_ARCH(AARCH64, aarch64*)

# i18n stuff for the PolicyKit policy files, heck whether intltool can be found, disable NLS otherwise
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
AS_IF([test x"$enable_nls" != xno -o "x$enable_polkit" != xno], [
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
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [systemd])

AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_GREP
AC_PROG_AWK

AC_PATH_PROG([M4], [m4])

AC_PATH_PROG([QUOTAON], [quotaon], [/usr/sbin/quotaon], [$PATH:/usr/sbin:/sbin])
AC_PATH_PROG([QUOTACHECK], [quotacheck], [/usr/sbin/quotacheck], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([SETCAP], [setcap], [/usr/sbin/setcap], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([KILL], [kill], [/usr/bin/kill], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([KMOD], [kmod], [/usr/bin/kmod], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([KEXEC], [kexec], [/usr/sbin/kexec], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([SULOGIN], [sulogin], [/usr/sbin/sulogin], [$PATH:/usr/sbin:/sbin])

AC_PATH_PROG([MOUNT_PATH], [mount], [/usr/bin/mount], [$PATH:/usr/sbin:/sbin])
AC_PATH_PROG([UMOUNT_PATH], [umount], [/usr/bin/umount], [$PATH:/usr/sbin:/sbin])

AS_IF([! ln --relative --help > /dev/null 2>&1], [AC_MSG_ERROR([*** ln doesn't support --relative ***])])

M4_DEFINES=

AC_CHECK_TOOL(OBJCOPY, objcopy)
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
        -Wundef \
        "-Wformat=2 -Wformat-security -Wformat-nonliteral" \
        -Wlogical-op \
        -Wmissing-include-dirs \
        -Wold-style-definition \
        -Wpointer-arith \
        -Winit-self \
        -Wdeclaration-after-statement \
        -Wfloat-equal \
        -Wsuggest-attribute=noreturn \
        -Werror=missing-prototypes \
        -Werror=implicit-function-declaration \
        -Werror=missing-declarations \
        -Werror=return-type \
        -Wstrict-prototypes \
        -Wredundant-decls \
        -Wmissing-noreturn \
        -Wshadow \
        -Wendif-labels \
        -Wstrict-aliasing=2 \
        -Wwrite-strings \
        -Wno-unused-parameter \
        -Wno-missing-field-initializers \
        -Wno-unused-result \
        -Wno-format-signedness \
        -Werror=overflow \
        -Wdate-time \
        -Wnested-externs \
        -ffast-math \
        -fno-common \
        -fdiagnostics-show-option \
        -fno-strict-aliasing \
        -fvisibility=hidden \
        -fstack-protector \
        -fstack-protector-strong \
        -fPIE \
        --param=ssp-buffer-size=4])

CC_CHECK_FLAG_APPEND([with_cflags], [CFLAGS], [-Werror=shadow], [
#include <time.h>
#include <inttypes.h>
typedef uint64_t usec_t;
usec_t now(clockid_t clock);
int main(void) {
        struct timespec now;
        return 0;
}
])

AS_CASE([$CC], [*clang*],
        [CC_CHECK_FLAGS_APPEND([with_cppflags], [CPPFLAGS], [\
               -Wno-typedef-redefinition \
               -Wno-gnu-variable-sized-type-not-at-end \
        ])])

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
               -flto])],
        [AC_MSG_RESULT([skipping -flto, optimization not enabled])])
AC_SUBST([OUR_CFLAGS], "$with_cflags $sanitizer_cflags")

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cppflags], [CPPFLAGS], [\
               -Wp,-D_FORTIFY_SOURCE=2])],
        [AC_MSG_RESULT([skipping -D_FORTIFY_SOURCE, optimization not enabled])])
AC_SUBST([OUR_CPPFLAGS], "$with_cppflags $sanitizer_cppflags")

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_ldflags], [LDFLAGS], [\
               -Wl,--gc-sections])],
        [AC_MSG_RESULT([skipping --gc-sections, optimization not enabled])])
AC_SUBST([OUR_CFLAGS], "$with_ldflags $sanitizer_cflags")

AS_CASE([$CFLAGS], [*-O[[12345sz\ ]]*],
        [CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
               -ffunction-sections -fdata-sections])],
        [AC_MSG_RESULT([skipping -ffunction/data-section, optimization not enabled])])
AC_SUBST([OUR_CFLAGS], "$with_cflags $sanitizer_cflags")

CC_CHECK_FLAGS_APPEND([with_ldflags], [LDFLAGS], [\
        -Wl,--as-needed \
        -Wl,--no-undefined \
        -Wl,-z,relro \
        -Wl,-z,now \
        -pie \
        -Wl,-fuse-ld=gold])
AC_SUBST([OUR_LDFLAGS], "$with_ldflags $sanitizer_ldflags")

AC_CHECK_SIZEOF(pid_t)
AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AC_CHECK_SIZEOF(time_t)
AC_CHECK_SIZEOF(dev_t)
AC_CHECK_SIZEOF(rlim_t,,[
       #include <sys/time.h>
       #include <sys/resource.h>
])

# ------------------------------------------------------------------------------
# we use python to build the man page index
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

# ------------------------------------------------------------------------------

AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])
AC_CHECK_HEADERS([linux/btrfs.h], [], [])
AC_CHECK_HEADERS([linux/memfd.h], [], [])

# unconditionally pull-in librt with old glibc versions
AC_SEARCH_LIBS([clock_gettime], [rt], [], [])

save_LIBS="$LIBS"
LIBS=
AC_SEARCH_LIBS([cap_init], [cap], [], [AC_MSG_ERROR([*** POSIX caps library not found])])
CAP_LIBS="$LIBS"
LIBS="$save_LIBS"
AC_SUBST(CAP_LIBS)

AC_CHECK_FUNCS([memfd_create])
AC_CHECK_FUNCS([__secure_getenv secure_getenv])
AC_CHECK_DECLS([gettid, pivot_root, name_to_handle_at, setns, getrandom, renameat2, kcmp, keyctl, key_serial_t, LO_FLAGS_PARTSCAN],
               [], [], [[
#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/loop.h>
#include <linux/random.h>
]])

AC_CHECK_DECLS([IFLA_INET6_ADDR_GEN_MODE,
                IFLA_MACVLAN_FLAGS,
                IFLA_IPVLAN_MODE,
                IFLA_VTI_REMOTE,
                IFLA_PHYS_PORT_ID,
                IFLA_BOND_AD_INFO,
                IFLA_VLAN_PROTOCOL,
                IFLA_VXLAN_REMCSUM_NOPARTIAL,
                IFLA_IPTUN_ENCAP_DPORT,
                IFLA_GRE_ENCAP_DPORT,
                IFLA_BRIDGE_VLAN_INFO,
                IFLA_BRPORT_LEARNING_SYNC,
                IFLA_BR_PRIORITY,
                NDA_IFINDEX,
                IFA_FLAGS],
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
#include <linux/if_addr.h>
#include <linux/neighbour.h>
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
have_utmp=yes
AC_ARG_ENABLE([utmp], AS_HELP_STRING([--disable-utmp], [disable utmp/wtmp log handling]),
        AS_CASE("x${enableval}",
                [xyes], [have_utmp=yes],
                [xno],  [have_utmp=no],
                AC_MSG_ERROR(bad value ${enableval} for --enable-utmp)))
AS_IF([test "x$have_utmp" = "xyes"], [AC_DEFINE(HAVE_UTMP, 1, [Define if utmp/wtmp support is enabled])])
AM_CONDITIONAL([HAVE_UTMP], [test "x$have_utmp" = "xyes"])

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
have_xkbcommon=no
AC_ARG_ENABLE(xkbcommon, AS_HELP_STRING([--disable-xkbcommon], [disable xkbcommon keymap support]))
if test "x$enable_xkbcommon" != "xno"; then
        PKG_CHECK_MODULES(XKBCOMMON, [ xkbcommon >= 0.3.0 ],
                [AC_DEFINE(HAVE_XKBCOMMON, 1, [Define if libxkbcommon is available]) have_xkbcommon=yes], have_xkbcommon=no)
        if test "x$have_xkbcommon" = xno -a "x$enable_xkbcommon" = xyes; then
                AC_MSG_ERROR([*** xkbcommon support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_XKBCOMMON, [test "$have_xkbcommon" = "yes"])

# ------------------------------------------------------------------------------
have_blkid=no
AC_ARG_ENABLE(blkid, AS_HELP_STRING([--disable-blkid], [disable blkid support]))
if test "x$enable_blkid" != "xno"; then
        PKG_CHECK_MODULES(BLKID, [ blkid >= 2.24 ],
                [AC_DEFINE(HAVE_BLKID, 1, [Define if blkid is available]) have_blkid=yes], have_blkid=no)
        if test "x$have_blkid" = xno -a "x$enable_blkid" = xyes; then
                AC_MSG_ERROR([*** blkid support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_BLKID, [test "$have_blkid" = "yes"])

# ------------------------------------------------------------------------------
have_libmount=no
PKG_CHECK_MODULES(MOUNT, [ mount >= 2.27 ],
        [AC_DEFINE(HAVE_LIBMOUNT, 1, [Define if libmount is available]) have_libmount=yes], have_libmount=no)
if test "x$have_libmount" = xno; then
        AC_MSG_ERROR([*** libmount support required but libraries not found])
fi
AM_CONDITIONAL(HAVE_LIBMOUNT, [test "$have_libmount" = "yes"])

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

AC_ARG_WITH([certificate-root],
        AS_HELP_STRING([--with-certificate-root=PATH],
                [Specify the prefix for TLS certificates [/etc/ssl]]),
        [CERTIFICATEROOT="$withval"],
        [CERTIFICATEROOT="/etc/ssl"])

AC_SUBST(CERTIFICATEROOT)

# ------------------------------------------------------------------------------
have_xz=no
AC_ARG_ENABLE(xz, AS_HELP_STRING([--disable-xz], [Disable optional XZ support]))
AS_IF([test "x$enable_xz" != "xno"], [
        PKG_CHECK_MODULES(XZ, [ liblzma ],
                [AC_DEFINE(HAVE_XZ, 1, [Define if XZ is available])
                 have_xz=yes],
                 have_xz=no)
        AS_IF([test "x$have_xz" = xno -a "x$enable_xz" = xyes],
              [AC_MSG_ERROR([*** XZ support requested but libraries not found])])
])
AM_CONDITIONAL(HAVE_XZ, [test "$have_xz" = "yes"])

# ------------------------------------------------------------------------------
have_zlib=no
AC_ARG_ENABLE(zlib, AS_HELP_STRING([--disable-zlib], [Disable optional ZLIB support]))
AS_IF([test "x$enable_zlib" != "xno"], [
        PKG_CHECK_MODULES(ZLIB, [ zlib ],
                [AC_DEFINE(HAVE_ZLIB, 1, [Define if ZLIB is available])
                 have_zlib=yes],
                 have_zlib=no)
        AS_IF([test "x$have_zlib" = xno -a "x$enable_zlib" = xyes],
              [AC_MSG_ERROR([*** ZLIB support requested but libraries not found])])
])
AM_CONDITIONAL(HAVE_ZLIB, [test "$have_zlib" = "yes"])

# ------------------------------------------------------------------------------
have_bzip2=no
AC_ARG_ENABLE(bzip2, AS_HELP_STRING([--enable-bzip2], [Disable optional BZIP2 support]))
AS_IF([test "x$enable_bzip2" != "xno"], [
        AC_CHECK_HEADERS(bzlib.h,
                [AC_DEFINE(HAVE_BZIP2, 1, [Define if BZIP2 is available])
                 have_bzip2=yes],
                [AS_IF([test "x$enable_bzip2" = xyes],
                       [AC_MSG_ERROR([*** BZIP2 support requested but headers not found])])]
        )
])
AM_CONDITIONAL(HAVE_BZIP2, [test "$have_bzip2" = "yes"])

# ------------------------------------------------------------------------------
have_lz4=no
AC_ARG_ENABLE(lz4, AS_HELP_STRING([--disable-lz4], [Disable optional LZ4 support]))
AS_IF([test "x$enable_lz4" != "xno"], [
        PKG_CHECK_MODULES(LZ4, [ liblz4 >= 125 ],
               [AC_DEFINE(HAVE_LZ4, 1, [Define in LZ4 is available])
                have_lz4=yes],
                have_lz4=no)
        AS_IF([test "x$have_lz4" = xno -a "x$enable_lz4" = xyes],
              [AC_MSG_ERROR([*** LZ4 support requested but libraries not found])])
])
AM_CONDITIONAL(HAVE_LZ4, [test "$have_lz4" = "yes"])

AM_CONDITIONAL(HAVE_COMPRESSION, [test "$have_xz" = "yes" -o "$have_lz4" = "yes"])

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
                M4_DEFINES="$M4_DEFINES -DHAVE_ACL"
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

have_smack_run_label=no
AC_ARG_WITH(smack-run-label,
AS_HELP_STRING([--with-smack-run-label=STRING],
        [run systemd --system itself with a specific SMACK label]),
        [AC_DEFINE_UNQUOTED(SMACK_RUN_LABEL, ["$withval"], [Run systemd itself with SMACK label]) have_smack_run_label=yes],
        [])

if test "x${have_smack_run_label}" = xyes; then
        M4_DEFINES="$M4_DEFINES -DHAVE_SMACK_RUN_LABEL"
fi

AC_ARG_WITH(smack-default-process-label,
AS_HELP_STRING([--with-smack-default-process-label=STRING],
        [default SMACK label for executed processes]),
        [AC_DEFINE_UNQUOTED(SMACK_DEFAULT_PROCESS_LABEL, ["$withval"], [Default SMACK label for executed processes])],
        [])

if test "x${have_smack}" = xyes ; then
        AC_DEFINE(HAVE_SMACK, 1, [Define if SMACK is available])
fi

AM_CONDITIONAL([HAVE_SMACK], [test "x$have_smack" = "xyes"])

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
        m4_define([AM_PATH_LIBGCRYPT_FAIL],
                [{ test "x$have_gcrypt" != xyes || AC_MSG_ERROR([*** GCRYPT headers not found.]); }]
        )
        m4_ifdef([AM_PATH_LIBGCRYPT], [AM_PATH_LIBGCRYPT(
                        [1.4.5],
                        [have_gcrypt=yes],
                        dnl  If we have the gcrypt m4 macros, but don't have
                        dnl  gcrypt, throw an error if gcrypt is explicitly
                        dnl  requested.
                        [AM_PATH_LIBGCRYPT_FAIL]
                )],
                dnl  If we don't have the gcrypt m4 macros, but build with
                dnl  gcrypt explicitly requested, throw an error.
                [AM_PATH_LIBGCRYPT_FAIL]
        )

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
AM_CONDITIONAL([HAVE_AUDIT], [test "x$have_audit" != xno])

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
have_libcurl=no
AC_ARG_ENABLE(libcurl, AS_HELP_STRING([--disable-libcurl], [disable libcurl support]))
if test "x$enable_libcurl" != "xno"; then
        PKG_CHECK_MODULES(LIBCURL, [libcurl],
                [AC_DEFINE(HAVE_LIBCURL, 1, [Define if libcurl is available]) have_libcurl=yes], have_libcurl=no)
        if test "x$have_libcurl" = xno -a "x$enable_libcurl" = xyes; then
                AC_MSG_ERROR([*** libcurl support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_LIBCURL, [test "$have_libcurl" = "yes"])

# ------------------------------------------------------------------------------
have_libidn=no
AC_ARG_ENABLE(libidn, AS_HELP_STRING([--disable-libidn], [Disable optional LIBIDN support]))
if test "x$enable_libidn" != "xno"; then
        PKG_CHECK_MODULES(LIBIDN, [libidn],
               [AC_DEFINE(HAVE_LIBIDN, 1, [Define if libidn is available])
                have_libidn=yes
                M4_DEFINES="$M4_DEFINES -DHAVE_LIBIDN"],
               [have_libidn=no])
        if test "x$have_libidn" = "xno" -a "x$enable_libidn" = "xyes"; then
                AC_MSG_ERROR([*** libidn support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_LIBIDN, [test "$have_libidn" = "yes"])

# ------------------------------------------------------------------------------
have_libiptc=no
AC_ARG_ENABLE(libiptc, AS_HELP_STRING([--disable-libiptc], [Disable optional LIBIPTC support]))
if test "x$enable_libiptc" != "xno"; then
        PKG_CHECK_MODULES(LIBIPTC, [libiptc],
               [AC_DEFINE(HAVE_LIBIPTC, 1, [Define if libiptc is available])
                have_libiptc=yes
                M4_DEFINES="$M4_DEFINES -DHAVE_LIBIPTC"],
               [have_libiptc=no])
        if test "x$have_libiptc" = "xno" -a "x$enable_libiptc" = "xyes"; then
                AC_MSG_ERROR([*** libiptc support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_LIBIPTC, [test "$have_libiptc" = "yes"])

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
have_firstboot=no
AC_ARG_ENABLE(firstboot, AS_HELP_STRING([--disable-firstboot], [disable firstboot support]))
if test "x$enable_firstboot" != "xno"; then
        have_firstboot=yes
fi
AM_CONDITIONAL(ENABLE_FIRSTBOOT, [test "$have_firstboot" = "yes"])

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
have_importd=no
AC_ARG_ENABLE(importd, AS_HELP_STRING([--disable-importd], [disable import daemon]))
if test "x$enable_importd" != "xno"; then
        have_importd=yes
fi
AM_CONDITIONAL(ENABLE_IMPORTD, [test "$have_importd" = "yes"])
AS_IF([test "$have_importd" = "yes"], [ AC_DEFINE(HAVE_IMPORTD, [1], [Importd support available]) ])

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
        M4_DEFINES="$M4_DEFINES -DENABLE_TIMESYNCD"
fi
AM_CONDITIONAL(ENABLE_TIMESYNCD, [test "$have_timesyncd" = "yes"])

AC_ARG_WITH(ntp-servers,
        AS_HELP_STRING([--with-ntp-servers=NTPSERVERS],
                [Space-separated list of default NTP servers]),
        [NTP_SERVERS="$withval"],
        [NTP_SERVERS="time1.google.com time2.google.com time3.google.com time4.google.com"
        AC_MSG_WARN([*** Using Google NTP servers.
                        Do not ship OSes or devices with these default settings.
                        See DISTRO_PORTING for details!])])

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
AS_IF([test "x$enable_resolved" != "xno"], [
        AC_CHECK_LIB([dl], [dlsym], [true], [AC_MSG_ERROR([*** Dynamic linking loader library not found])])

        have_resolved=yes
        M4_DEFINES="$M4_DEFINES -DENABLE_RESOLVED"
])
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
        M4_DEFINES="$M4_DEFINES -DENABLE_NETWORKD"
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
AC_CHECK_TOOL(EFI_CC, gcc)

EFI_ARCH=`echo $host | sed "s/\(-\).*$//"`

AM_COND_IF(ARCH_IA32, [
        EFI_ARCH=ia32
        EFI_MACHINE_TYPE_NAME=ia32])

AM_COND_IF(ARCH_X86_64, [
        EFI_MACHINE_TYPE_NAME=x64])

AM_COND_IF(ARCH_AARCH64, [
        EFI_MACHINE_TYPE_NAME=aa64])

AC_SUBST([EFI_ARCH])
AC_SUBST([EFI_MACHINE_TYPE_NAME])

have_gnuefi=no
AC_ARG_ENABLE(gnuefi, AS_HELP_STRING([--enable-gnuefi], [Disable optional gnuefi support]))
AS_IF([test "x$enable_gnuefi" != "xno"], [
        AC_CHECK_HEADERS(efi/${EFI_ARCH}/efibind.h,
                [AC_DEFINE(HAVE_GNUEFI, 1, [Define if gnuefi is available])
                 have_gnuefi=yes],
                [AS_IF([test "x$enable_gnuefi" = xyes],
                       [AC_MSG_ERROR([*** gnuefi support requested but headers not found])])
        ])

        efiroot=$(echo $(cd /usr/lib/$(${EFI_CC} -print-multi-os-directory); pwd))

        EFI_LIB_DIR="$efiroot"
        AC_ARG_WITH(efi-libdir,
                AS_HELP_STRING([--with-efi-libdir=PATH], [Path to EFI lib directory]),
                [EFI_LIB_DIR="$withval"], [EFI_LIB_DIR="$efiroot"]
        )
        AC_SUBST([EFI_LIB_DIR])

        have_efi_lds=no
        AC_ARG_WITH(efi-ldsdir,
                AS_HELP_STRING([--with-efi-ldsdir=PATH], [Path to EFI lds directory]),
                [EFI_LDS_DIR="$withval" && AS_IF([test -f "${EFI_LDS_DIR}/elf_${EFI_ARCH}_efi.lds"],
                        [have_efi_lds=yes])],
                [AS_FOR([DIR], [EFI_LDS_DIR], ["${EFI_LIB_DIR}/gnuefi" "${EFI_LIB_DIR}"],
                        [AS_IF([test -f "${EFI_LDS_DIR}/elf_${EFI_ARCH}_efi.lds"],
                                       [have_efi_lds=yes && break])])])
        AS_IF([test "x$have_efi_lds" = xyes],
              [AC_SUBST([EFI_LDS_DIR])],
              [AS_IF([test "x$enable_gnuefi" = xyes],
                     [AC_MSG_ERROR([*** gnuefi support requested but files not found])],
                     [have_gnuefi=no])])

        AC_ARG_WITH(efi-includedir,
                AS_HELP_STRING([--with-efi-includedir=PATH], [Path to EFI include directory]),
                [EFI_INC_DIR="$withval"], [EFI_INC_DIR="/usr/include"]
        )
        AC_SUBST([EFI_INC_DIR])
])
AM_CONDITIONAL(HAVE_GNUEFI, [test "x$have_gnuefi" = xyes])

# ------------------------------------------------------------------------------
have_kdbus=no
AC_ARG_ENABLE(kdbus, AS_HELP_STRING([--disable-kdbus], [do not connect to kdbus by default]))
if test "x$enable_kdbus" != "xno"; then
        AC_DEFINE(ENABLE_KDBUS, 1, [Define if kdbus is to be connected to by default])
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

        AC_FUNC_SELECT_ARGTYPES
        AC_CHECK_FUNCS([gethostbyaddr gethostbyname gettimeofday inet_ntoa memset select socket strcspn strdup strerror strncasecmp strcasecmp strspn])

        have_myhostname=yes
fi
AM_CONDITIONAL(HAVE_MYHOSTNAME, [test "$have_myhostname" = "yes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE(hwdb, [AC_HELP_STRING([--disable-hwdb], [disable hardware database support])],
       enable_hwdb=$enableval, enable_hwdb=yes)
AM_CONDITIONAL(ENABLE_HWDB, [test x$enable_hwdb = xyes])

# ------------------------------------------------------------------------------
have_manpages=no
AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages], [disable manpages]))
AS_IF([test "x$enable_manpages" != xno], [
       have_manpages=yes
       AC_PATH_PROG([XSLTPROC], [xsltproc])
       AS_IF([test -z "$XSLTPROC"],
             AC_MSG_ERROR([*** xsltproc is required for man pages]))
])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$have_manpages" = "xyes"])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE(hibernate,
       [AC_HELP_STRING([--disable-hibernate], [disable hibernation support])],
       enable_hibernate=$enableval, enable_hibernate=yes)
AM_CONDITIONAL(ENABLE_HIBERNATE, [test x$enable_hibernate = xyes])

# ------------------------------------------------------------------------------
AC_ARG_ENABLE(ldconfig,
       [AC_HELP_STRING([--disable-ldconfig], [disable ldconfig])],
       enable_ldconfig=$enableval, enable_ldconfig=yes)
AM_CONDITIONAL(ENABLE_LDCONFIG, [test x$enable_ldconfig = xyes])

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
        [with_dbuspolicydir=${sysconfdir}/dbus-1/system.d])
AX_NORMALIZE_PATH([with_dbuspolicydir])

AC_ARG_WITH([dbussessionservicedir],
        AS_HELP_STRING([--with-dbussessionservicedir=DIR], [D-Bus session service directory]),
        [],
        [with_dbussessionservicedir=${datadir}/dbus-1/services])
AX_NORMALIZE_PATH([with_dbussessionservicedir])

AC_ARG_WITH([dbussystemservicedir],
        AS_HELP_STRING([--with-dbussystemservicedir=DIR], [D-Bus system service directory]),
        [],
        [with_dbussystemservicedir=${datadir}/dbus-1/system-services])
AX_NORMALIZE_PATH([with_dbussystemservicedir])

AC_ARG_WITH([bashcompletiondir],
        AS_HELP_STRING([--with-bashcompletiondir=DIR], [Bash completions directory]),
        [],
        [AS_IF([$($PKG_CONFIG --exists bash-completion)], [
                with_bashcompletiondir=$($PKG_CONFIG --variable=completionsdir bash-completion)
        ] , [
                with_bashcompletiondir=${datadir}/bash-completion/completions
        ])])
AM_CONDITIONAL(ENABLE_BASH_COMPLETION, [test "$with_bashcompletiondir" != "no"])
AX_NORMALIZE_PATH([with_bashcompletiondir])

AC_ARG_WITH([zshcompletiondir],
        AS_HELP_STRING([--with-zshcompletiondir=DIR], [Zsh completions directory]),
        [], [with_zshcompletiondir=${datadir}/zsh/site-functions])
AM_CONDITIONAL(ENABLE_ZSH_COMPLETION, [test "$with_zshcompletiondir" != "no"])
AX_NORMALIZE_PATH([with_zshcompletiondir])

AC_ARG_WITH([rootprefix],
        AS_HELP_STRING([--with-rootprefix=DIR], [rootfs directory prefix for config files and kernel modules]),
        [], [with_rootprefix=${ac_default_prefix}])
# --with-rootprefix= (empty) should default to "/" but AX_NORMALIZE_PATH
# defaults those to ".", solve that here for now until we can find a suitable
# fix for AX_NORMALIZE_PATH upstream at autoconf-archive.
# See: https://github.com/systemd/systemd/issues/54
if test "x${with_rootprefix}" = "x"; then
        with_rootprefix="/"
fi
AX_NORMALIZE_PATH([with_rootprefix])

AC_ARG_WITH([rootlibdir],
        AS_HELP_STRING([--with-rootlibdir=DIR], [Root directory for libraries necessary for boot]),
        [],
        [with_rootlibdir=${libdir}])
AX_NORMALIZE_PATH([with_rootlibdir])

AC_ARG_WITH([pamlibdir],
        AS_HELP_STRING([--with-pamlibdir=DIR], [Directory for PAM modules]),
        [],
        [with_pamlibdir=${with_rootlibdir}/security])
AX_NORMALIZE_PATH([with_pamlibdir])

AC_ARG_WITH([pamconfdir],
        AS_HELP_STRING([--with-pamconfdir=DIR], [Directory for PAM configuration]),
        [],
        [with_pamconfdir=${sysconfdir}/pam.d])
AX_NORMALIZE_PATH([with_pamconfdir])

AC_ARG_ENABLE([split-usr],
        AS_HELP_STRING([--enable-split-usr], [Assume that /bin, /sbin aren\'t symlinks into /usr]),
        [],
        [AS_IF([test "x${ac_default_prefix}" != "x${with_rootprefix}"], [
                enable_split_usr=yes
        ], [
                enable_split_usr=no
        ])])

AC_ARG_WITH([dkr-index-url],
        [AS_HELP_STRING([--dkr-index-url=URL], [Specify the default index URL to use for image downloads])],
        [DEFAULT_DKR_INDEX_URL="\"$withval\""],
        [DEFAULT_DKR_INDEX_URL="NULL"])

AC_DEFINE_UNQUOTED(DEFAULT_DKR_INDEX_URL, [$DEFAULT_DKR_INDEX_URL], [Default index URL to use for image downloads])
AC_SUBST(DEFAULT_DKR_INDEX_URL)

AS_IF([test "x${enable_split_usr}" = "xyes"], [
        AC_DEFINE(HAVE_SPLIT_USR, 1, [Define if /bin, /sbin aren't symlinks into /usr])
])
AM_CONDITIONAL(ENABLE_SPLIT_USR, [test "x${enable_split_usr}" = "xyes"])

# work around intltool-update issues during 'make distcheck'
AS_IF([test "x$0" != "x./configure"], [
        AC_SUBST([INTLTOOL_UPDATE], [/bin/true])
])

# QEMU and OVMF UEFI firmware
AS_IF([test x"$cross_compiling" = "xyes"], [], [
        AC_PATH_PROG([QEMU], [qemu-system-x86_64])
        AC_CHECK_FILE([/usr/share/qemu/bios-ovmf.bin], [QEMU_BIOS=/usr/share/qemu/bios-ovmf.bin],
                [AC_CHECK_FILE([/usr/share/qemu-ovmf/bios.bin], [QEMU_BIOS=/usr/share/qemu-ovmf/bios.bin])])
        AC_SUBST([QEMU_BIOS])
])

AC_ARG_ENABLE(tests,
        [AC_HELP_STRING([--disable-tests], [disable tests])],
        enable_tests=$enableval, enable_tests=yes)
AM_CONDITIONAL(ENABLE_TESTS, [test x$enable_tests = xyes])

AC_ARG_ENABLE(debug,
        [AC_HELP_STRING([--enable-debug@<:@=LIST@:>@], [enable extra debugging (hashmap,mmap-cache)])],
        [if test "x$enableval" = "xyes"; then
                enableval="hashmap,mmap-cache"
        fi
        saved_ifs="$IFS"
        IFS="$IFS$PATH_SEPARATOR,"
        for name in $enableval; do
                case $name in
                hashmap)
                        enable_debug_hashmap=yes
                        ;;
                mmap-cache)
                        enable_debug_mmap_cache=yes
                        ;;
                esac
        done
        IFS="$saved_ifs"],[])

enable_debug=""
AS_IF([test x$enable_debug_hashmap = xyes], [
        AC_DEFINE(ENABLE_DEBUG_HASHMAP, 1, [Define if hashmap debugging is to be enabled])
        enable_debug="hashmap $enable_debug"
])
AS_IF([test x$enable_debug_mmap_cache = xyes], [
        AC_DEFINE(ENABLE_DEBUG_MMAP_CACHE, 1, [Define if mmap cache debugging is to be enabled])
        enable_debug="mmap-cache $enable_debug"
])
test -z "$enable_debug" && enable_debug="none"

AC_SUBST([dbuspolicydir], [$with_dbuspolicydir])
AC_SUBST([dbussessionservicedir], [$with_dbussessionservicedir])
AC_SUBST([dbussystemservicedir], [$with_dbussystemservicedir])
AC_SUBST([bashcompletiondir], [$with_bashcompletiondir])
AC_SUBST([zshcompletiondir], [$with_zshcompletiondir])
AC_SUBST([pamlibdir], [$with_pamlibdir])
AC_SUBST([pamconfdir], [$with_pamconfdir])
AC_SUBST([rootprefix], [$with_rootprefix])
AC_SUBST([rootlibdir], [$with_rootlibdir])

AC_CONFIG_FILES([
        Makefile
        po/Makefile.in
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
        ZLIB:                    ${have_zlib}
        XZ:                      ${have_xz}
        LZ4:                     ${have_lz4}
        BZIP2:                   ${have_bzip2}
        ACL:                     ${have_acl}
        GCRYPT:                  ${have_gcrypt}
        QRENCODE:                ${have_qrencode}
        MICROHTTPD:              ${have_microhttpd}
        GNUTLS:                  ${have_gnutls}
        libcurl:                 ${have_libcurl}
        libidn:                  ${have_libidn}
        libiptc:                 ${have_libiptc}
        ELFUTILS:                ${have_elfutils}
        binfmt:                  ${have_binfmt}
        vconsole:                ${have_vconsole}
        bootchart:               ${have_bootchart}
        quotacheck:              ${have_quotacheck}
        tmpfiles:                ${have_tmpfiles}
        sysusers:                ${have_sysusers}
        firstboot:               ${have_firstboot}
        randomseed:              ${have_randomseed}
        backlight:               ${have_backlight}
        rfkill:                  ${have_rfkill}
        logind:                  ${have_logind}
        machined:                ${have_machined}
        importd:                 ${have_importd}
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
        gnuefi:                  ${have_gnuefi}
        efi arch:                ${EFI_ARCH}
        EFI machine type:        ${EFI_MACHINE_TYPE_NAME}
        EFI CC                   ${EFI_CC}
        EFI libdir:              ${EFI_LIB_DIR}
        EFI ldsdir:              ${EFI_LDS_DIR}
        EFI includedir:          ${EFI_INC_DIR}
        kmod:                    ${have_kmod}
        xkbcommon:               ${have_xkbcommon}
        blkid:                   ${have_blkid}
        libmount:                ${have_libmount}
        dbus:                    ${have_dbus}
        nss-myhostname:          ${have_myhostname}
        hwdb:                    ${enable_hwdb}
        kdbus:                   ${have_kdbus}
        Python:                  ${have_python}
        man pages:               ${have_manpages}
        test coverage:           ${have_coverage}
        Split /usr:              ${enable_split_usr}
        SysV compatibility:      ${SYSTEM_SYSV_COMPAT}
        compatibility libraries: ${have_compat_libs}
        utmp/wtmp support:       ${have_utmp}
        ldconfig support:        ${enable_ldconfig}
        hibernate support:       ${enable_hibernate}
        extra debugging:         ${enable_debug}

        prefix:                  ${prefix}
        rootprefix:              ${with_rootprefix}
        sysconf dir:             ${sysconfdir}
        datarootdir:             ${datarootdir}
        includedir:              ${includedir}
        lib dir:                 ${libdir}
        rootlib dir:             ${with_rootlibdir}
        SysV init scripts:       ${SYSTEM_SYSVINIT_PATH}
        SysV rc?.d directories:  ${SYSTEM_SYSVRCND_PATH}
        Build Python:            ${PYTHON}
        PAM modules dir:         ${with_pamlibdir}
        PAM configuration dir:   ${with_pamconfdir}
        D-Bus policy dir:        ${with_dbuspolicydir}
        D-Bus session dir:       ${with_dbussessionservicedir}
        D-Bus system dir:        ${with_dbussystemservicedir}
        Bash completions dir:    ${with_bashcompletiondir}
        Zsh completions dir:     ${with_zshcompletiondir}
        Extra start script:      ${RC_LOCAL_SCRIPT_PATH_START}
        Extra stop script:       ${RC_LOCAL_SCRIPT_PATH_STOP}
        Debug shell:             ${SUSHELL} @ ${DEBUGTTY}
        TTY GID:                 ${TTY_GID}
        Maximum System UID:      ${SYSTEM_UID_MAX}
        Maximum System GID:      ${SYSTEM_GID_MAX}
        Certificate root:        ${CERTIFICATEROOT}
        Default dkr Index        ${DEFAULT_DKR_INDEX_URL}

        CFLAGS:                  ${OUR_CFLAGS} ${CFLAGS}
        CPPFLAGS:                ${OUR_CPPFLAGS} ${CPPFLAGS}
        LDFLAGS:                 ${OUR_LDFLAGS} ${LDFLAGS}
])
