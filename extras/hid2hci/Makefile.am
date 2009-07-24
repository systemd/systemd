include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	hid2hci

dist_udevrules_DATA = \
	70-hid2hci.rules

hid2hci_SOURCES = \
	hid2hci.c \
	../../libudev/libudev.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c \
	../../libudev/libudev-device.c \
	../../libudev/libudev-enumerate.c

hid2hci_LDADD = \
	@LIBUSB_LIBS@
