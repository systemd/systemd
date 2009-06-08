AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/libudev \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

AM_CFLAGS =

AM_LDFLAGS = \
	-Wl,--as-needed
