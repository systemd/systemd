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
])

AC_OUTPUT
AC_MSG_RESULT([
	udev $VERSION
	========

	prefix:			${prefix}
	exec_prefix:		${exec_prefix}
	udev_prefix:		${udev_prefix}
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

	xsltproc:		${XSLTPROC}
])
