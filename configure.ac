AC_INIT([udev],
	[134],
	[linux-hotplug@vger.kernel.org])
AC_PREREQ(2.60)
AC_CONFIG_SRCDIR([udev/udevd.c])
AM_INIT_AUTOMAKE([check-news foreign 1.9 dist-bzip2])
AC_GNU_SOURCE
AC_DISABLE_STATIC
AC_SYS_LARGEFILE
AC_PROG_LIBTOOL

dnl /* libudev version */
LIBUDEV_LT_CURRENT=0
LIBUDEV_LT_REVISION=6
LIBUDEV_LT_AGE=0
AC_SUBST(LIBUDEV_LT_CURRENT)
AC_SUBST(LIBUDEV_LT_REVISION)
AC_SUBST(LIBUDEV_LT_AGE)

dnl /* libvolume_id version */
VOLID_LT_CURRENT=1
VOLID_LT_REVISION=6
VOLID_LT_AGE=0
AC_SUBST(VOLID_LT_CURRENT)
AC_SUBST(VOLID_LT_REVISION)
AC_SUBST(VOLID_LT_AGE)

AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_CHECK_LIB(c, inotify_init,
	[AC_DEFINE([HAVE_INOTIFY], 1, [inotify available])],
	[AC_MSG_WARN([inotify support disabled])])

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
	AS_HELP_STRING([--with-selinux], [compile with SELinux support]),
	[], with_selinux=no)
if test "x$with_selinux" = xyes; then
	LIBS_save=$LIBS
	AC_CHECK_LIB(selinux, getprevcon,
		[],
		AC_MSG_ERROR([SELinux selected but libselinux not found]))
	LIBS=$LIBS_save
	AC_DEFINE(USE_SELINUX, [1] ,[compile with SELinux support])
	SELINUX_LIBS="-lselinux"
fi
AC_SUBST([SELINUX_LIBS])
AM_CONDITIONAL(USE_SELINUX, [test "x$with_selinux" = xyes], [compile with SELinux support])

AC_ARG_ENABLE(debug,
	AS_HELP_STRING([--enable-debug], [turn on debugging]),
	[], enable_debug=no)
if test "x$enable_debug" = "xyes"; then
	AC_DEFINE(DEBUG, [1] ,[Compile in debug messages])
	DEBUG_CFLAGS="-DDEBUG"
fi
AC_SUBST(DEBUG_CFLAGS)

AC_ARG_ENABLE(logging,
	AS_HELP_STRING([--disable-logging], [turn off logging/syslog]),
	[], enable_logging=yes)
if test "x$enable_logging" != "xno"; then
	AC_DEFINE(USE_LOG, [1] ,[Use logging/syslog])
fi

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
	Makefile
	udev/Makefile
	udev/lib/Makefile
	udev/lib/libudev.pc
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
	extras/volume_id/Makefile
	extras/volume_id/lib/Makefile
	extras/volume_id/lib/libvolume_id.pc
])
AC_OUTPUT

echo "
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
"
