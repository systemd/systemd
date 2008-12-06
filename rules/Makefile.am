include $(top_srcdir)/Makefile.am.inc

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	rules.d/50-udev-default.rules \
	rules.d/60-persistent-storage.rules \
	rules.d/60-persistent-storage-tape.rules \
	rules.d/60-persistent-serial.rules \
	rules.d/60-persistent-input.rules \
	rules.d/60-persistent-v4l.rules \
	rules.d/80-drivers.rules \
	rules.d/95-udev-late.rules

install-data-local:
	-mkdir -p $(DESTDIR)$(sysconfdir)/udev/rules.d

EXTRA_DIST = \
	packages \
	redhat \
	suse \
	gentoo
