include $(top_srcdir)/Makefile.am.inc

SUBDIRS = \
	docs

noinst_PROGRAMS = \
	test-libudev

test_libudev_SOURCES = \
	test-libudev.c

test_libudev_LDADD = \
	libudev.la

lib_LTLIBRARIES = \
	libudev.la

include_HEADERS =\
	libudev.h

libudev_la_SOURCES =\
	libudev-private.h \
	libudev.c \
	libudev-list.c \
	libudev-util.c \
	libudev-device.c \
	libudev-enumerate.c \
	libudev-monitor.c \
	libudev-queue.c

noinst_LTLIBRARIES = \
	libudev-private.la

libudev_private_la_SOURCES =\
	$(libudev_la_SOURCES) \
	libudev-ctrl.c \
	libudev-util-private.c \
	libudev-device-private.c \
	libudev-queue-private.c

if WITH_SELINUX
libudev_private_la_SOURCES += \
	libudev-selinux-private.c
endif

LT_CURRENT=5
LT_REVISION=0
LT_AGE=5
libudev_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-export-symbols $(top_srcdir)/libudev/exported_symbols

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libudev.pc

EXTRA_DIST = \
	exported_symbols

# move lib from $(libdir) to $(rootlib_execdir) and update devel link, if needed
install-exec-hook:
	if test "$(libdir)" != "$(rootlib_execdir)"; then \
		mkdir -p $(DESTDIR)$(rootlib_execdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libudev.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlib_execdir)/$$so_img_name $(DESTDIR)$(libdir)/libudev.so && \
		mv $(DESTDIR)$(libdir)/libudev.so.* $(DESTDIR)$(rootlib_execdir); \
	fi

uninstall-hook:
	rm -f $(DESTDIR)$(rootlib_execdir)/libudev.so*
