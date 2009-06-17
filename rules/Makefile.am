include $(top_srcdir)/Makefile.am.inc

dist_udevrules_DATA = \
	rules.d/50-udev-default.rules \
	rules.d/60-persistent-storage.rules \
	rules.d/60-persistent-storage-tape.rules \
	rules.d/60-persistent-serial.rules \
	rules.d/60-persistent-input.rules \
	rules.d/60-persistent-alsa.rules \
	rules.d/80-drivers.rules \
	rules.d/95-udev-late.rules

if ENABLE_EXTRAS
dist_udevrules_DATA += \
	rules.d/75-net-description.rules \
	rules.d/75-tty-description.rules \
	rules.d/78-sound-card.rules
endif

install-data-local:
	-mkdir -p $(DESTDIR)$(sysconfdir)/udev/rules.d

EXTRA_DIST = \
	packages \
	redhat \
	suse \
	gentoo
