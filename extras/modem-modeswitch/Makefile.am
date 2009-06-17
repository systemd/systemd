include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	modem-modeswitch

modem_modeswitch_SOURCES = \
	modem-modeswitch.c \
	utils.c \
	utils.h \
	ma8280p_us.c \
	ma8280p_us.h \
	option.c \
	option.h

modem_modeswitch_CPPFLAGS = \
	$(AM_CPPFLAGS) $(LIBUSB_CFLAGS)

modem_modeswitch_LDADD = \
	$(LIBUSB_LIBS)

dist_udevrules_DATA = \
	61-option-modem-modeswitch.rules \
	61-mobile-action.rules
