include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = hid2hci

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = 70-hid2hci.rules

hid2hci_SOURCES = hid2hci.c
hid2hci_LDADD = @LIBUSB_LIBS@
