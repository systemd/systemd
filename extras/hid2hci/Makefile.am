include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	hid2hci

dist_udevrules_DATA = \
	70-hid2hci.rules

hid2hci_SOURCES = \
	hid2hci.c

hid2hci_LDADD = \
	$(top_builddir)/libudev/libudev-private.la \
	@LIBUSB_LIBS@
