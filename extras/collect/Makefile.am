udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	collect

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

distclean-local:
	rm -f Makefile.in

