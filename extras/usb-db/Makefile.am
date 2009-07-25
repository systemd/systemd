include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	usb-db pci-db

usb_db_SOURCES = \
	usb-db.c

usb_db_CPPFLAGS = \
	$(AM_CPPFLAGS) -DUSB_DATABASE=\"$(USB_DATABASE)\" -DBUILD_FOR_USB

usb_db_LDADD = \
	$(top_builddir)/libudev/libudev-private.la


pci_db_SOURCES = \
	$(usb_db_SOURCES)

pci_db_CPPFLAGS = \
	$(AM_CPPFLAGS) -DPCI_DATABASE=\"$(PCI_DATABASE)\" -DBUILD_FOR_PCI

pci_db_LDADD = \
	$(top_builddir)/libudev/libudev-private.la
