include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	udev-acl

udev_acl_SOURCES = \
	udev-acl.c

udev_acl_CPPFLAGS = \
	$(AM_CPPFLAGS) $(GLIB_CFLAGS)

udev_acl_LDADD = \
	-lacl $(top_builddir)/libudev/libudev-private.la $(GLIB_LIBS)

dist_udevrules_DATA = 70-acl.rules

install-exec-hook:
	mkdir -p $(DESTDIR)$(prefix)/lib/ConsoleKit/run-session.d
	ln -sf $(libexecdir)/udev-acl $(DESTDIR)$(prefix)/lib/ConsoleKit/run-session.d/udev-acl.ck
