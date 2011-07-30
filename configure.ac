AC_PREREQ(2.60)
AC_INIT([udev],
	[173],
	[linux-hotplug@vger.kernel.org],
	[udev],
	[http://www.kernel.org/pub/linux/utils/kernel/hotplug/udev.html])
AC_CONFIG_SRCDIR([udev/udevd.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([check-news foreign 1.11 -Wall -Wno-portability silent-rules tar-pax dist-bzip2 subdir-objects])
AC_DISABLE_STATIC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT
AC_PROG_AWK
GTK_DOC_CHECK(1.10)
AC_PREFIX_DEFAULT([/usr])
AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([POSIX RT library not found])])

AC_ARG_WITH([rootlibdir],
	AS_HELP_STRING([--with-rootlibdir=DIR], [rootfs directory to install shared libraries]),
	[], [with_rootlibdir=$libdir])
AC_SUBST([rootlib_execdir], [$with_rootlibdir])

AC_ARG_WITH([selinux],
	AS_HELP_STRING([--with-selinux], [enable SELinux support]),
	[], [with_selinux=no])
if test "x$with_selinux" = xyes; then
	LIBS_save=$LIBS
	AC_CHECK_LIB(selinux, getprevcon,
		[],
		AC_MSG_ERROR([SELinux selected but libselinux not found]))
	LIBS=$LIBS_save
	SELINUX_LIBS="-lselinux -lsepol"
	AC_DEFINE(WITH_SELINUX, [1] ,[SELinux support.])
fi
AC_SUBST([SELINUX_LIBS])
AM_CONDITIONAL(WITH_SELINUX, [test "x$with_selinux" = xyes])

AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug], [enable debug messages]),
	[], [enable_debug=no])
if test "x$enable_debug" = "xyes"; then
	AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
fi

AC_ARG_ENABLE([logging],
	AS_HELP_STRING([--disable-logging], [disable system logging]),
	[], enable_logging=yes)
if test "x$enable_logging" = "xyes"; then
	AC_DEFINE(ENABLE_LOGGING, [1], [System logging.])
fi

AC_ARG_WITH(firmware-path,
	AS_HELP_STRING([--with-firmware-path=DIR[[[:DIR[...]]]]],
	   [Firmware search path (default=/lib/firmware/updates:/lib/firmware)]),
	[], [with_firmware_path="/lib/firmware/updates:/lib/firmware"])
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
AC_SUBST([FIRMWARE_PATH], [$FIRMWARE_PATH])

AC_ARG_WITH([systemdsystemunitdir],
	AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
	[], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
if test "x$with_systemdsystemunitdir" != xno; then
	AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi
AM_CONDITIONAL(WITH_SYSTEMD, [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])

# ------------------------------------------------------------------------------
# GUdev - libudev gobject interface
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([gudev],
	AS_HELP_STRING([--disable-gudev], [disable Gobject libudev support]),
	[], [enable_gudev=yes])
if test "x$enable_gudev" = xyes; then
	PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.22.0 gobject-2.0 >= 2.22.0])
fi

AC_ARG_ENABLE([introspection],
	AS_HELP_STRING([--disable-introspection], [disable GObject introspection]),
	[], [enable_introspection=yes])
if test "x$enable_introspection" = xyes; then
	PKG_CHECK_MODULES([INTROSPECTION], [gobject-introspection-1.0 >= 0.6.2])
	AC_DEFINE([ENABLE_INTROSPECTION], [1], [enable GObject introspection support])
	AC_SUBST([G_IR_SCANNER], [$($PKG_CONFIG --variable=g_ir_scanner gobject-introspection-1.0)])
	AC_SUBST([G_IR_COMPILER], [$($PKG_CONFIG --variable=g_ir_compiler gobject-introspection-1.0)])
	AC_SUBST([G_IR_GENERATE], [$($PKG_CONFIG --variable=g_ir_generate gobject-introspection-1.0)])
	AC_SUBST([GIRDIR], [$($PKG_CONFIG --define-variable=datadir=${datadir} --variable=girdir gobject-introspection-1.0)])
	AC_SUBST([GIRTYPELIBDIR], [$($PKG_CONFIG --define-variable=libdir=${libdir} --variable=typelibdir gobject-introspection-1.0)])
fi
AM_CONDITIONAL([ENABLE_INTROSPECTION], [test "x$enable_introspection" = xyes])

AM_CONDITIONAL([ENABLE_GUDEV], [test "x$enable_gudev" = xyes])

# ------------------------------------------------------------------------------
# usb/pci-db - read vendor/device string database
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([hwdb],
	AS_HELP_STRING([--disable-hwdb], [disable hardware database support]),
	[], [enable_hwdb=yes])
if test "x$enable_hwdb" = xyes; then
	if test "x$cross_compiling" = "xno" ; then
		AC_CHECK_FILES([/usr/share/pci.ids], [pciids=/usr/share/pci.ids])
		AC_CHECK_FILES([/usr/share/hwdata/pci.ids], [pciids=/usr/share/hwdata/pci.ids])
		AC_CHECK_FILES([/usr/share/misc/pci.ids], [pciids=/usr/share/misc/pci.ids])
	fi

	AC_ARG_WITH(usb-ids-path,
		[AS_HELP_STRING([--with-usb-ids-path=DIR], [Path to usb.ids file])],
		[USB_DATABASE=${withval}],
		[if test -n "$usbids" ; then
			USB_DATABASE="$usbids"
		else
			PKG_CHECK_MODULES(USBUTILS, usbutils >= 0.82)
			AC_SUBST([USB_DATABASE], [$($PKG_CONFIG --variable=usbids usbutils)])
		fi])
	AC_MSG_CHECKING([for USB database location])
	AC_MSG_RESULT([$USB_DATABASE])
	AC_SUBST(USB_DATABASE)

	AC_ARG_WITH(pci-ids-path,
		[AS_HELP_STRING([--with-pci-ids-path=DIR], [Path to pci.ids file])],
		[PCI_DATABASE=${withval}],
		[if test -n "$pciids" ; then
			PCI_DATABASE="$pciids"
		else
			AC_MSG_ERROR([pci.ids not found, try --with-pci-ids-path=])
		fi])
	AC_MSG_CHECKING([for PCI database location])
	AC_MSG_RESULT([$PCI_DATABASE])
	AC_SUBST(PCI_DATABASE)
fi
AM_CONDITIONAL([ENABLE_HWDB], [test "x$enable_hwdb" = xyes])

# ------------------------------------------------------------------------------
# keymap - map custom hardware's multimedia keys
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([keymap],
	AS_HELP_STRING([--disable-keymap], [disable keymap fixup support]),
	[], [enable_keymap=yes])
if test "x$enable_keymap" = xyes; then
	AC_PATH_PROG([GPERF], [gperf])
	if test -z "$GPERF"; then
		AC_MSG_ERROR([gperf is needed])
	fi

	AC_CHECK_HEADER([linux/input.h], [:], AC_MSG_ERROR([kernel headers not found]))
	AC_SUBST([INCLUDE_PREFIX], [$(echo '#include <linux/input.h>' | eval $ac_cpp -E - | sed -n '/linux\/input.h/ {s:.*"\(.*\)/linux/input.h".*:\1:; p; q}')])
fi
AM_CONDITIONAL([ENABLE_KEYMAP], [test "x$enable_keymap" = xyes])

# ------------------------------------------------------------------------------
# mtd_probe - autoloads FTL module for mtd devices
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([mtd_probe],
	AS_HELP_STRING([--disable-mtd_probe], [disable MTD support]),
	[], [enable_mtd_probe=yes])
AM_CONDITIONAL([ENABLE_MTD_PROBE], [test "x$enable_mtd_probe" = xyes])

# ------------------------------------------------------------------------------
# rule_generator - persistent network and optical device rule generator
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([rule_generator],
	AS_HELP_STRING([--disable-rule_generator], [disable persistent network, cdrom support]),
	[], [enable_rule_generator=yes])
AM_CONDITIONAL([ENABLE_RULE_GENERATOR], [test "x$enable_rule_generator" = xyes])

# ------------------------------------------------------------------------------
# udev_acl - apply ACLs for users with local forground sessions
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([udev_acl],
	AS_HELP_STRING([--enable-udev_acl], [enable local user acl permissions support]),
	[], [enable_udev_acl=no])
if test "x$enable_udev_acl" = xyes; then
	AC_CHECK_LIB([acl], [acl_init], [:], AC_MSG_ERROR([libacl not found]))
	AC_CHECK_HEADER([acl/libacl.h], [:], AC_MSG_ERROR([libacl header not found]))

	PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.22.0 gobject-2.0 >= 2.22.0])
fi
AM_CONDITIONAL([ENABLE_UDEV_ACL], [test "x$enable_udev_acl" = xyes])

# ------------------------------------------------------------------------------
# create_floppy_devices - historical floppy kernel device nodes (/dev/fd0h1440, ...)
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([floppy],
	AS_HELP_STRING([--enable-floppy], [enable legacy floppy support]),
	[], [enable_floppy=no])
AM_CONDITIONAL([ENABLE_FLOPPY], [test "x$enable_floppy" = xyes])

# ------------------------------------------------------------------------------
# edd_id - create /dev/disk/by-id/edd-* links for BIOS EDD data
# ------------------------------------------------------------------------------
AC_ARG_ENABLE([edd],
	AS_HELP_STRING([--enable-edd], [enable disk edd support]),
	[], [enable_edd=no])
AM_CONDITIONAL([ENABLE_EDD], [test "x$enable_edd" = xyes])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
	Makefile
	udev/udev.pc
	init/udev.service
	init/udev-trigger.service
	init/udev-settle.service
	libudev/libudev.pc
	libudev/docs/Makefile
	libudev/docs/version.xml
	extras/gudev/gudev-1.0.pc
	extras/gudev/docs/Makefile
	extras/gudev/docs/version.xml
])

AC_OUTPUT
AC_MSG_RESULT([
	udev $VERSION
	========

	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	sbindir:		${sbindir}
	libdir:			${libdir}
	rootlibdir:		${rootlib_execdir}
	libexecdir:		${libexecdir}
	datarootdir:		${datarootdir}
	mandir:			${mandir}
	includedir:		${includedir}
	include_prefix:		${INCLUDE_PREFIX}
	systemdsystemunitdir:	${systemdsystemunitdir}
	firmware path:		${FIRMWARE_PATH}

	compiler:		${CC}
	cflags:			${CFLAGS}
	ldflags:		${LDFLAGS}
	xsltproc:		${XSLTPROC}
	gperf:			${GPERF}

	logging:		${enable_logging}
	debug:			${enable_debug}
	selinux:		${with_selinux}

	gudev:			${enable_gudev}
	gintrospection:		${enable_introspection}
	keymap:			${enable_keymap}
	hwdb:			${enable_hwdb}
	  usb.ids:		${USB_DATABASE}
	  pci.ids:		${PCI_DATABASE}
	mtd_probe:		${enable_mtd_probe}
	rule_generator:		${enable_rule_generator}
	udev_acl:		${enable_udev_acl}
	floppy:			${enable_floppy}
	edd:			${enable_edd}
])
