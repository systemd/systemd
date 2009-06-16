AC_INIT([udev],
	[143],
	[linux-hotplug@vger.kernel.org])
AC_PREREQ(2.60)
AM_INIT_AUTOMAKE([check-news foreign 1.9 dist-bzip2])
AC_DISABLE_STATIC
AC_USE_SYSTEM_EXTENSIONS
dnl AM_SILENT_RULES
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_LIBTOOL
GTK_DOC_CHECK(1.10)

dnl /* prefix is /usr, exec_prefix is /, if overridden exec_prefix follows prefix */
AC_PREFIX_DEFAULT([/usr])
test "$prefix" = NONE && test "$exec_prefix" = NONE && exec_prefix=

AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_ARG_WITH(udev-prefix,
	AS_HELP_STRING([--with-udev-prefix=DIR], [add prefix to internal udev path names]),
	[], [with_udev_prefix='${exec_prefix}'])
udev_prefix=$with_udev_prefix
AC_SUBST(udev_prefix)

AC_ARG_WITH(libdir-name,
	AS_HELP_STRING([--with-libdir-name=DIR], [name of the arch lib directory]),
	[], [with_libdir_name=lib])
libdir_name=$with_libdir_name
AC_SUBST(libdir_name)

AC_ARG_WITH(selinux,
	AS_HELP_STRING([--with-selinux], [enable SELinux support]),
	[], with_selinux=no)
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

AC_ARG_ENABLE(debug,
	AS_HELP_STRING([--enable-debug], [enable debug messages]),
	[], enable_debug=no)
if test "x$enable_debug" = "xyes"; then
	AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
fi

AC_ARG_ENABLE(logging,
	AS_HELP_STRING([--disable-logging], [disable system logging]),
	[], enable_logging=yes)
if test "x$enable_logging" = "xyes"; then
	AC_DEFINE(ENABLE_LOGGING, [1], [System logging.])
fi

AC_ARG_ENABLE([extras],
	AS_HELP_STRING([--enable-extras], [enable extras with external dependencies]),
	[], [enable_extras=no])
if test "x$enable_extras" = xyes; then
	PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.7.0 gobject-2.0 >= 2.7.0])
	AC_SUBST([GLIB_CFLAGS])
	AC_SUBST([GLIB_LIBS])

	AC_CHECK_LIB([acl], [acl_init], [:], AC_MSG_ERROR([libacl not found]))
	AC_CHECK_HEADER([acl/libacl.h], [:], AC_MSG_ERROR([libacl header not found]))

	PKG_CHECK_MODULES(LIBUSB, libusb >= 0.1.12)
	AC_SUBST(LIBUSB_CFLAGS)
	AC_SUBST(LIBUSB_LIBS)
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
	libudev/Makefile
	libudev/libudev.pc
	libudev/docs/Makefile
	libudev/docs/version.xml
	udev/Makefile
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
	extras/gudev/Makefile
	extras/gudev/gudev-1.0.pc
	extras/gudev/docs/Makefile
	extras/gudev/docs/version.xml
])

AC_OUTPUT
AC_MSG_RESULT([
	udev $VERSION
	========

	prefix:			${prefix}
	exec_prefix:		${exec_prefix}
	udev_prefix:		${udev_prefix}
	libdir:			${libdir}
	libdir_name:		${libdir_name}
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

	xsltproc:		${XSLTPROC}
])
