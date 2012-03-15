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

AC_INIT([systemd],[44],[systemd-devel@lists.freedesktop.org])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PREFIX_DEFAULT([/usr])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects check-news])

AC_SUBST(PACKAGE_URL, [http://www.freedesktop.org/wiki/Software/systemd])

AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], "$host", [Canonical host string.])
AS_IF([test "x$host_cpu" = "xmips" || test "x$host_cpu" = "xmipsel" ||
       test "x$host_cpu" = "xmips64" || test "x$host_cpu" = "xmips64el"],
      [AC_DEFINE(ARCH_MIPS, [], [Whether on mips arch])])

AM_SILENT_RULES([yes])

# i18n stuff for the PolicyKit policy files
IT_PROG_INTLTOOL([0.40.0])

GETTEXT_PACKAGE=systemd
AC_SUBST(GETTEXT_PACKAGE)

AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_GREP
AC_PROG_AWK

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL

AC_CHECK_TOOL(OBJCOPY, objcopy)
AC_CHECK_TOOL(STRINGS, strings)
AC_CHECK_TOOL(GPERF, gperf)
if test -z "$GPERF" ; then
        AC_MSG_ERROR([*** gperf not found])
fi

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
        -Wstrict-prototypes \
        -Wredundant-decls \
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

LT_PREREQ(2.2)
LT_INIT

AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([*** POSIX RT library not found])])
AC_SEARCH_LIBS([dlsym], [dl], [], [AC_MSG_ERROR([*** Dynamic linking loader library not found])])

save_LIBS="$LIBS"
LIBS=
AC_SEARCH_LIBS([cap_init], [cap], [], [AC_MSG_ERROR([*** POSIX caps library not found])])
AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])
CAP_LIBS="$LIBS"
LIBS="$save_LIBS"
AC_SUBST(CAP_LIBS)

# This makes sure pkg.m4 is available.
m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

PKG_CHECK_MODULES(UDEV, [ libudev >= 172 ])
PKG_CHECK_MODULES(DBUS, [ dbus-1 >= 1.3.2 ])
PKG_CHECK_MODULES(KMOD, [ libkmod >= 5 ])

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

have_selinux=no
AC_ARG_ENABLE(selinux, AS_HELP_STRING([--disable-selinux], [Disable optional SELINUX support]))
if test "x$enable_selinux" != "xno"; then
        PKG_CHECK_MODULES(SELINUX, [ libselinux ],
                [AC_DEFINE(HAVE_SELINUX, 1, [Define if SELinux is available]) have_selinux=yes], have_selinux=no)
        if test "x$have_selinux" = xno -a "x$enable_selinux" = xyes; then
                AC_MSG_ERROR([*** SELinux support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_SELINUX, [test "$have_selinux" = "yes"])

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

AC_ARG_ENABLE([tcpwrap],
        AS_HELP_STRING([--disable-tcpwrap],[Disable optional TCP wrappers support]),
                [case "${enableval}" in
                        yes) have_tcpwrap=yes ;;
                        no) have_tcpwrap=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-tcpwrap) ;;
                esac],
                [have_tcpwrap=auto])

if test "x${have_tcpwrap}" != xno ; then
        ACX_LIBWRAP
        if test "x${LIBWRAP_LIBS}" = x ; then
                if test "x$have_tcpwrap" = xyes ; then
                        AC_MSG_ERROR([*** TCP wrappers support not found.])
                fi
                have_tcpwrap=no
        else
                have_tcpwrap=yes
        fi
else
        LIBWRAP_LIBS=
fi
AC_SUBST(LIBWRAP_LIBS)

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
        else
                have_pam=no
        fi
else
        PAM_LIBS=
fi
AC_SUBST(PAM_LIBS)
AM_CONDITIONAL([HAVE_PAM], [test "x$have_pam" != xno])

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

have_libcryptsetup=no
AC_ARG_ENABLE(libcryptsetup, AS_HELP_STRING([--disable-libcryptsetup], [disable libcryptsetup tools]))
if test "x$enable_libcryptsetup" != "xno"; then
        PKG_CHECK_MODULES(LIBCRYPTSETUP, [ libcryptsetup ],
                [AC_DEFINE(HAVE_LIBCRYPTSETUP, 1, [Define if libcryptsetup is available]) have_libcryptsetup=yes], have_libcryptsetup=no)
        if test "x$have_libcryptsetup" = xno -a "x$enable_libcryptsetup" = xyes; then
                AC_MSG_ERROR([*** libcryptsetup support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_LIBCRYPTSETUP, [test "$have_libcryptsetup" = "yes"])

have_binfmt=no
AC_ARG_ENABLE(binfmt, AS_HELP_STRING([--disable-binfmt], [disable binfmt tool]))
if test "x$enable_binfmt" != "xno"; then
        have_binfmt=yes
fi
AM_CONDITIONAL(ENABLE_BINFMT, [test "$have_binfmt" = "yes"])

have_vconsole=no
AC_ARG_ENABLE(vconsole, AS_HELP_STRING([--disable-vconsole], [disable vconsole tool]))
if test "x$enable_vconsole" != "xno"; then
        have_vconsole=yes
fi
AM_CONDITIONAL(ENABLE_VCONSOLE, [test "$have_vconsole" = "yes"])

have_readahead=no
AC_ARG_ENABLE(readahead, AS_HELP_STRING([--disable-readahead], [disable readahead tools]))
if test "x$enable_readahead" != "xno"; then
        have_readahead=yes
fi
AM_CONDITIONAL(ENABLE_READAHEAD, [test "$have_readahead" = "yes"])

have_quotacheck=no
AC_ARG_ENABLE(quotacheck, AS_HELP_STRING([--disable-quotacheck], [disable quotacheck tools]))
if test "x$enable_quotacheck" != "xno"; then
        have_quotacheck=yes
fi
AM_CONDITIONAL(ENABLE_QUOTACHECK, [test "$have_quotacheck" = "yes"])

have_randomseed=no
AC_ARG_ENABLE(randomseed, AS_HELP_STRING([--disable-randomseed], [disable randomseed tools]))
if test "x$enable_randomseed" != "xno"; then
        have_randomseed=yes
fi
AM_CONDITIONAL(ENABLE_RANDOMSEED, [test "$have_randomseed" = "yes"])

have_logind=no
AC_ARG_ENABLE(logind, AS_HELP_STRING([--disable-logind], [disable login daemon]))
if test "x$enable_logind" != "xno"; then
        have_logind=yes
fi
AM_CONDITIONAL(ENABLE_LOGIND, [test "$have_logind" = "yes"])
AS_IF([test "$have_logind" = "yes"], [ AC_DEFINE(HAVE_LOGIND, [1], [Logind support available]) ])

have_hostnamed=no
AC_ARG_ENABLE(hostnamed, AS_HELP_STRING([--disable-hostnamed], [disable hostname daemon]))
if test "x$enable_hostnamed" != "xno"; then
        have_hostnamed=yes
fi
AM_CONDITIONAL(ENABLE_HOSTNAMED, [test "$have_hostnamed" = "yes"])

have_timedated=no
AC_ARG_ENABLE(timedated, AS_HELP_STRING([--disable-timedated], [disable timedate daemon]))
if test "x$enable_timedated" != "xno"; then
        have_timedated=yes
fi
AM_CONDITIONAL(ENABLE_TIMEDATED, [test "$have_timedated" = "yes"])

have_localed=no
AC_ARG_ENABLE(localed, AS_HELP_STRING([--disable-localed], [disable locale daemon]))
if test "x$enable_localed" != "xno"; then
        have_localed=yes
fi
AM_CONDITIONAL(ENABLE_LOCALED, [test "$have_localed" = "yes"])

have_coredump=no
AC_ARG_ENABLE(coredump, AS_HELP_STRING([--disable-coredump], [disable coredump hook]))
if test "x$enable_coredump" != "xno"; then
        have_coredump=yes
fi
AM_CONDITIONAL(ENABLE_COREDUMP, [test "$have_coredump" = "yes"])

have_manpages=no
AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages], [disable manpages]))
if test "x$enable_manpages" != "xno"; then
        have_manpages=yes
fi
AM_CONDITIONAL(ENABLE_MANPAGES, [test "$have_manpages" = "yes"])

AC_PATH_PROG([XSLTPROC], [xsltproc])
AM_CONDITIONAL(HAVE_XSLTPROC, test x"$XSLTPROC" != x)

AC_PATH_PROG([M4], [m4])

AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO],[Specify the distribution to target: One of fedora, suse, debian, ubuntu, arch, gentoo, slackware, altlinux, mandriva, meego, mageia, angstrom or other]))
if test "z$with_distro" = "z"; then
        if test "$cross_compiling" = yes; then
                AC_MSG_WARN([Target distribution cannot be reliably detected when cross-compiling. You should specify it with --with-distro (see $0 --help for recognized distros)])
        else
                with_distro=$($GREP '^ID=' /etc/os-release | $SED 's/ID=//');
        fi
        if test "z$with_distro" = "z"; then
                with_distro=other
        fi
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]' `
AC_DEFINE_UNQUOTED(DISTRIBUTION, ["${with_distro}"], [Target Distribution])

# Location of the init scripts as mandated by LSB
SYSTEM_SYSVINIT_PATH=/etc/init.d
SYSTEM_SYSVRCND_PATH=/etc/rc.d

M4_DEFINES=
have_plymouth=no

case $with_distro in
        fedora)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                AC_DEFINE(TARGET_FEDORA, [], [Target is Fedora/RHEL])
                M4_DEFINES=-DTARGET_FEDORA=1
                have_plymouth=yes
                ;;
        opensuse|suse)
                SYSTEM_SYSVRCND_PATH=/etc/init.d
                AC_DEFINE(TARGET_SUSE, [], [Target is openSUSE/SLE])
                M4_DEFINES=-DTARGET_SUSE=1
                have_plymouth=yes
                ;;
        debian)
                SYSTEM_SYSVRCND_PATH=/etc
                AC_DEFINE(TARGET_DEBIAN, [], [Target is Debian])
                M4_DEFINES=-DTARGET_DEBIAN=1
                ;;
        ubuntu)
                SYSTEM_SYSVRCND_PATH=/etc
                AC_DEFINE(TARGET_UBUNTU, [], [Target is Ubuntu])
                M4_DEFINES=-DTARGET_UBUNTU=1
                ;;
        arch)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d
                SYSTEM_SYSVRCND_PATH=/etc
                AC_DEFINE(TARGET_ARCH, [], [Target is ArchLinux])
                M4_DEFINES=-DTARGET_ARCH=1
                ;;
        gentoo)
                SYSTEM_SYSVINIT_PATH=
                SYSTEM_SYSVRCND_PATH=
                AC_DEFINE(TARGET_GENTOO, [], [Target is Gentoo])
                M4_DEFINES=-DTARGET_GENTOO=1
                ;;
        slackware)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                AC_DEFINE(TARGET_SLACKWARE, [], [Target is Slackware])
                M4_DEFINES=-DTARGET_SLACKWARE=1
                ;;
        frugalware)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d
                AC_DEFINE(TARGET_FRUGALWARE, [], [Target is Frugalware])
                M4_DEFINES=-DTARGET_FRUGALWARE=1
                have_plymouth=yes
                ;;
        altlinux)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                AC_DEFINE(TARGET_ALTLINUX, [], [Target is ALTLinux])
                M4_DEFINES=-DTARGET_ALTLINUX=1
                have_plymouth=yes
                ;;
        mandriva)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                AC_DEFINE(TARGET_MANDRIVA, [], [Target is Mandriva])
                M4_DEFINES=-DTARGET_MANDRIVA=1
                have_plymouth=yes
                ;;
        meego)
                SYSTEM_SYSVINIT_PATH=
                SYSTEM_SYSVRCND_PATH=
                AC_DEFINE(TARGET_MEEGO, [], [Target is MeeGo])
                M4_DEFINES=-DTARGET_MEEGO=1
                ;;
        angstrom)
                SYSTEM_SYSVRCND_PATH=/etc
                AC_DEFINE(TARGET_ANGSTROM, [], [Target is Ångström])
                M4_DEFINES=-DTARGET_ANGSTROM=1
                ;;
        mageia)
                SYSTEM_SYSVINIT_PATH=/etc/rc.d/init.d
                AC_DEFINE(TARGET_MAGEIA, [], [Target is Mageia])
                M4_DISTRO_FLAG=-DTARGET_MAGEIA=1
                have_plymouth=yes
                ;;
        other)
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

AC_SUBST(SYSTEM_SYSVINIT_PATH)
AC_SUBST(SYSTEM_SYSVRCND_PATH)
AC_SUBST(M4_DEFINES)

if test "x${SYSTEM_SYSVINIT_PATH}" != "x" -a "x${SYSTEM_SYSVRCND_PATH}" != "x"; then
        AC_DEFINE(HAVE_SYSV_COMPAT, [], [SysV init scripts and rcN.d links are supported.])
        SYSTEM_SYSV_COMPAT="yes"
        M4_DEFINES="$M4_DEFINES -DHAVE_SYSV_COMPAT"
elif test "x${SYSTEM_SYSVINIT_PATH}" != "x" -o "x${SYSTEM_SYSVRCND_PATH}" != "x"; then
        AC_MSG_ERROR([*** You need both --with-sysvinit-path=PATH and --with-sysvrcd-path=PATH to enable SysV compatibility support, or both empty to disable it.])
else
        SYSTEM_SYSV_COMPAT="no"
fi

AC_ARG_WITH([tty-gid],
        [AS_HELP_STRING([--with-tty-gid=GID],
                [Specify the numeric GID of the 'tty' group])],
        [AC_DEFINE_UNQUOTED(TTY_GID, [$withval], [GID of the 'tty' group])],
        [])

AC_ARG_ENABLE(plymouth, AS_HELP_STRING([--enable-plymouth], [enable plymouth support]))
if test -n "$enable_plymouth"; then
        have_plymouth="$enable_plymouth"
fi

AM_CONDITIONAL(TARGET_FEDORA, test x"$with_distro" = xfedora)
AM_CONDITIONAL(TARGET_SUSE, test x"$with_distro" = xsuse)
AM_CONDITIONAL(TARGET_DEBIAN, test x"$with_distro" = xdebian)
AM_CONDITIONAL(TARGET_UBUNTU, test x"$with_distro" = xubuntu)
AM_CONDITIONAL(TARGET_DEBIAN_OR_UBUNTU, test x"$with_distro" = xdebian -o x"$with_distro" = xubuntu)
AM_CONDITIONAL(TARGET_ARCH, test x"$with_distro" = xarch)
AM_CONDITIONAL(TARGET_GENTOO, test x"$with_distro" = xgentoo)
AM_CONDITIONAL(TARGET_SLACKWARE, test x"$with_distro" = xslackware)
AM_CONDITIONAL(TARGET_FRUGALWARE, test x"$with_distro" = xfrugalware)
AM_CONDITIONAL(TARGET_ALTLINUX, test x"$with_distro" = xaltlinux)
AM_CONDITIONAL(TARGET_MANDRIVA, test x"$with_distro" = xmandriva)
AM_CONDITIONAL(TARGET_MEEGO, test x"$with_distro" = xmeego)
AM_CONDITIONAL(TARGET_ANGSTROM, test x"$with_distro" = xangstrom)
AM_CONDITIONAL(TARGET_MAGEIA, test x"$with_distro" = xmageia)

AM_CONDITIONAL(HAVE_PLYMOUTH, test "$have_plymouth" = "yes")
AM_CONDITIONAL(HAVE_SYSV_COMPAT, test "$SYSTEM_SYSV_COMPAT" = "yes")

AC_ARG_WITH([dbuspolicydir],
        AS_HELP_STRING([--with-dbuspolicydir=DIR], [D-Bus policy directory]),
        [],
        [with_dbuspolicydir=`pkg-config --variable=sysconfdir dbus-1`/dbus-1/system.d])

AC_ARG_WITH([dbussessionservicedir],
        AS_HELP_STRING([--with-dbussessionservicedir=DIR], [D-Bus session service directory]),
        [],
        [with_dbussessionservicedir=`pkg-config --variable=session_bus_services_dir dbus-1`])

AC_ARG_WITH([dbussystemservicedir],
        AS_HELP_STRING([--with-dbussystemservicedir=DIR], [D-Bus system service directory]),
        [],
        [with_dbussystemservicedir=`pkg-config --variable=session_bus_services_dir dbus-1`/../system-services])

AC_ARG_WITH([dbusinterfacedir],
        AS_HELP_STRING([--with-dbusinterfacedir=DIR], [D-Bus interface directory]),
        [],
        [with_dbusinterfacedir=`pkg-config --variable=session_bus_services_dir dbus-1`/../interfaces])

AC_ARG_WITH([udevrulesdir],
        AS_HELP_STRING([--with-udevrulesdir=DIR], [Directory for udev rules]),
        [],
        [with_udevrulesdir=`pkg-config --variable=udevdir udev`/rules.d])

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

AC_SUBST([dbuspolicydir], [$with_dbuspolicydir])
AC_SUBST([dbussessionservicedir], [$with_dbussessionservicedir])
AC_SUBST([dbussystemservicedir], [$with_dbussystemservicedir])
AC_SUBST([dbusinterfacedir], [$with_dbusinterfacedir])
AC_SUBST([udevrulesdir], [$with_udevrulesdir])
AC_SUBST([pamlibdir], [$with_pamlibdir])
AC_SUBST([rootprefix], [$with_rootprefix])
AC_SUBST([rootlibdir], [$with_rootlibdir])

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE_NAME $VERSION

        Distribution:            ${with_distro}
        SysV compatibility:      ${SYSTEM_SYSV_COMPAT}
        SysV init scripts:       ${SYSTEM_SYSVINIT_PATH}
        SysV rc?.d directories:  ${SYSTEM_SYSVRCND_PATH}
        libcryptsetup:           ${have_libcryptsetup}
        tcpwrap:                 ${have_tcpwrap}
        PAM:                     ${have_pam}
        AUDIT:                   ${have_audit}
        IMA:                     ${have_ima}
        SELinux:                 ${have_selinux}
        XZ:                      ${have_xz}
        ACL:                     ${have_acl}
        binfmt:                  ${have_binfmt}
        vconsole:                ${have_vconsole}
        readahead:               ${have_readahead}
        quotacheck:              ${have_quotacheck}
        randomseed:              ${have_randomseed}
        logind:                  ${have_logind}
        hostnamed:               ${have_hostnamed}
        timedated:               ${have_timedated}
        localed:                 ${have_localed}
        coredump:                ${have_coredump}
        plymouth:                ${have_plymouth}
        prefix:                  ${prefix}
        rootprefix:              ${with_rootprefix}
        libexec dir:             ${libexecdir}
        lib dir:                 ${libdir}
        rootlib dir:             ${with_rootlibdir}
        PAM modules dir:         ${with_pamlibdir}
        udev rules dir:          ${with_udevrulesdir}
        D-Bus policy dir:        ${with_dbuspolicydir}
        D-Bus session dir:       ${with_dbussessionservicedir}
        D-Bus system dir:        ${with_dbussystemservicedir}
        D-Bus interfaces dir:    ${with_dbusinterfacedir}
        Split /usr:              ${enable_split_usr}
        man pages:               ${have_manpages}
])
