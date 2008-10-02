AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\" \
	-D_LIBUDEV_COMPILATION

AM_CFLAGS =

AM_LDFLAGS = \
	-Wl,--as-needed
