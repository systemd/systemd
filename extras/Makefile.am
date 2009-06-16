include $(top_srcdir)/Makefile.am.inc

SUBDIRS = \
	ata_id \
	cdrom_id \
	edd_id \
	path_id \
	firmware \
	collect \
	floppy \
	fstab_import \
	rule_generator \
	scsi_id \
	usb_id \
	v4l_id

if ENABLE_EXTRAS
SUBDIRS += \
	udev-acl \
	usb-db \
	hid2hci \
	gudev
endif
