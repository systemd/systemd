AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/libudev \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\"

AM_CFLAGS =

AM_LDFLAGS = \
	-Wl,--as-needed

udevrulesdir = \
	$(libexecdir)/rules.d

