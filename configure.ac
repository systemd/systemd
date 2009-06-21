AC_INIT([udev], [14], [linux-hotplug@vger.kernel.org])
AC_PREREQ(2.60)
AM_INIT_AUTOMAKE([check-news foreign 1.9 dist-bzip2])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_DISABLE_STATIC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_LIBTOOL
AC_PROG_AWK
GTK_DOC_CHECK(1.10)
AC_PREFIX_DEFAULT([/usr])
AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_ARG_WITH([rootlibdir],
	AS_HELP_STRING([--with-rootlibdir=DIR], [rootfs directory to install shared libraries]),
	[], [with_rootlibdir=$libdir])
AC_SUBST([rootlibdir], [$with_rootlibdir])

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

AC_ARG_ENABLE([extras],
	AS_HELP_STRING([--disable-extras], [disable extras with external dependencies]),
	[], [enable_extras=yes])
if test "x$enable_extras" = xyes; then
	AC_PATH_PROG([GPERF], [gperf])
	if test -z "$GPERF"; then
		AC_MSG_ERROR([gperf is needed])
	fi

	PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.7.0 gobject-2.0 >= 2.7.0])
	AC_SUBST([GLIB_CFLAGS])
	AC_SUBST([GLIB_LIBS])

	AC_CHECK_LIB([acl], [acl_init], [:], AC_MSG_ERROR([libacl not found]))
	AC_CHECK_HEADER([acl/libacl.h], [:], AC_MSG_ERROR([libacl header not found]))

	PKG_CHECK_MODULES(LIBUSB, libusb >= 0.1.12)
	AC_SUBST(LIBUSB_CFLAGS)
	AC_SUBST(LIBUSB_LIBS)

	PKG_CHECK_MODULES(USBUTILS, usbutils >= 0.82)
	AC_SUBST([USB_DATABASE], [$($PKG_CONFIG --variable=usbids usbutils)])

	AC_CHECK_FILES([/usr/share/pci.ids], [pciids=/usr/share/pci.ids])
	AC_CHECK_FILES([/usr/share/hwdata/pci.ids], [pciids=/usr/share/hwdata/pci.ids])
	AC_CHECK_FILES([/usr/share/misc/pci.ids], [pciids=/usr/share/misc/pci.ids])
	AC_ARG_WITH(pci-ids-path,
		AS_HELP_STRING([--pci-ids-path=DIR], [Path to pci.ids file]),
		[PCI_DATABASE=${withval}],
		[if test -n "$pciids" ; then
			PCI_DATABASE="$pciids"
		else
			AC_MSG_ERROR([pci.ids not found, try --with-pci-ids-path=])
		fi])
	AC_SUBST(PCI_DATABASE)
fi
AM_CONDITIONAL([ENABLE_EXTRAS], [test "x$enable_extras" = xyes])

AC_ARG_ENABLE([introspection],
	AS_HELP_STRING([--enable-introspection], [enable GObject introspection]),
	[], [enable_introspection=no])
if test "x$enable_introspection" = xyes; then
	PKG_CHECK_MODULES([INTROSPECTION], [gobject-introspection-1.0 >= 0.6.2])
	AC_DEFINE([ENABLE_INTROSPECTION], [1], [enable GObject introspection support])
	AC_SUBST([G_IR_SCANNER], [$($PKG_CONFIG --variable=g_ir_scanner gobject-introspection-1.0)])
	AC_SUBST([G_IR_COMPILER], [$($PKG_CONFIG --variable=g_ir_compiler gobject-introspection-1.0)])
	AC_SUBST([G_IR_GENERATE], [$($PKG_CONFIG --variable=g_ir_generate gobject-introspection-1.0)])
	AC_SUBST([GIRDIR], [$($PKG_CONFIG --variable=girdir gobject-introspection-1.0)])
	AC_SUBST([GIRTYPELIBDIR], [$($PKG_CONFIG --variable=typelibdir gobject-introspection-1.0)])
fi
AM_CONDITIONAL([ENABLE_INTROSPECTION], [test "x$enable_introspection" = xyes])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
	Makefile
	docs/Makefile
	libudev/Makefile
	libudev/libudev.pc
	libudev/docs/Makefile
	libudev/docs/version.xml
	udev/Makefile
	udev/udev.pc
	rules/Makefile
	extras/Makefile
	extras/ata_id/Makefile
	extras/cdrom_id/Makefile
	extras/edd_id/Makefile
	extras/path_id/Makefile
	extras/firmware/Makefile
	extras/collect/Makefile
	extras/floppy/Makefile
	extras/fstab_import/Makefile
	extras/rule_generator/Makefile
	extras/scsi_id/Makefile
	extras/usb_id/Makefile
	extras/v4l_id/Makefile
	extras/hid2hci/Makefile
	extras/udev-acl/Makefile
	extras/usb-db/Makefile
	extras/gudev/Makefile
	extras/gudev/gudev-1.0.pc
	extras/gudev/docs/Makefile
	extras/gudev/docs/version.xml
	extras/keymap/Makefile
	extras/modem-modeswitch/Makefile
])

AC_OUTPUT
AC_MSG_RESULT([
	udev $VERSION
	========

	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	sbindir:		${sbindir}
	libdir:			${libdir}
	rootlibdir:		${rootlibdir}
	libexecdir:		${libexecdir}

	datarootdir:		${datarootdir}
	mandir:			${mandir}
	includedir:		${includedir}

	logging:		${enable_logging}
	debug:			${enable_debug}
	selinux:		${with_selinux}

	compiler:		${CC}
	cflags:			${CFLAGS}
	ldflags:		${LDFLAGS}

	extras:			${enable_extras}
	gintrospection:		${enable_introspection}

	usb.ids:		${USB_DATABASE}
	pci.ids:		${PCI_DATABASE}

	xsltproc:		${XSLTPROC}
	gperf:			${GPERF}
])
