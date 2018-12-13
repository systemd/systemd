#
#  This file is part of systemd-boot.
#
#  Copyright (C) 2018 James Hilliard <james.hilliard1@gmail.com>
#
#  systemd-boot is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd-boot is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

AC_INIT([systemd-boot],
        [239],
        [systemd-devel@lists.freedesktop.org],
        [systemd-boot],
        [https://freedesktop.org/wiki/Software/systemd/systemd-boot/])

AC_CONFIG_SRCDIR([efi/boot.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_PREFIX_DEFAULT([/usr])

AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects])
AM_SILENT_RULES([yes])

AC_CANONICAL_HOST
AC_SYS_LARGEFILE

AC_PROG_CC

AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL

AC_PROG_MKDIR_P

dnl Define ARCH_<NAME> conditionals
SET_ARCH(X86_64, x86_64*)
SET_ARCH(IA32, i*86*)
SET_ARCH(MIPS, mips*)
SET_ARCH(AARCH64, aarch64*)

AC_CHECK_TOOL(OBJCOPY, objcopy)

# QEMU and OVMF UEFI firmware
AS_IF([test x"$cross_compiling" = "xyes"], [], [
        AC_PATH_PROG([QEMU], [qemu-system-x86_64])
        AC_CHECK_FILE([/usr/share/qemu/bios-ovmf.bin], [QEMU_BIOS=/usr/share/qemu/bios-ovmf.bin],
                [AC_CHECK_FILE([/usr/share/qemu-ovmf/bios.bin], [QEMU_BIOS=/usr/share/qemu-ovmf/bios.bin])])
        AC_SUBST([QEMU_BIOS])
])

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
have_efi=no
AC_ARG_ENABLE(efi, AS_HELP_STRING([--disable-efi], [disable systemd-boot and bootctl (EFI support)]))
if test "x$enable_efi" != "xno"; then
        AC_DEFINE(ENABLE_EFI, 1, [Define if systemd-boot and bootctl are to be enabled])
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
AC_ARG_ENABLE(gnuefi, AS_HELP_STRING([--enable-gnuefi], [enable optional gnuefi support]))
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
                AS_HELP_STRING([--with-efi-libdir=PATH], [path to EFI lib directory]),
                [EFI_LIB_DIR="$withval"], [EFI_LIB_DIR="$efiroot"]
        )
        AC_SUBST([EFI_LIB_DIR])

        have_efi_lds=no
        AC_ARG_WITH(efi-ldsdir,
                AS_HELP_STRING([--with-efi-ldsdir=PATH], [path to EFI lds directory]),
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
                AS_HELP_STRING([--with-efi-includedir=PATH], [path to EFI include directory]),
                [EFI_INC_DIR="$withval"], [EFI_INC_DIR="/usr/include"]
        )
        AC_SUBST([EFI_INC_DIR])
])
AM_CONDITIONAL(HAVE_GNUEFI, [test "x$have_gnuefi" = xyes])


# ------------------------------------------------------------------------------
AC_CONFIG_FILES([
        Makefile
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE_NAME $VERSION

        prefix:                  ${prefix}
        arch:                    $ARCH
        EFI machine type:        $MACHINE_TYPE_NAME

        EFI libdir:              ${EFI_LIB_DIR}
        EFI ldsdir:              ${EFI_LDS_DIR}
        EFI includedir:          ${EFI_INC_DIR}

        blkid:                   ${have_blkid}

        QEMU:                    ${QEMU}
        QEMU OVMF:               ${QEMU_BIOS}
])
