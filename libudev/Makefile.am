include $(top_srcdir)/Makefile.am.inc

SUBDIRS = \
	docs

noinst_PROGRAMS = \
	test-libudev

test_libudev_SOURCES = \
	test-libudev.c

test_libudev_LDADD = \
	libudev.la

rootlibdir = $(exec_prefix)/$(libdir_name)
rootlib_LTLIBRARIES = \
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

LT_CURRENT=4
LT_REVISION=0
LT_AGE=4
libudev_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-export-symbols $(top_srcdir)/libudev/exported_symbols

pkgconfigdir = $(prefix)/$(libdir_name)/pkgconfig
pkgconfig_DATA = libudev.pc

EXTRA_DIST = \
	exported_symbols

# move devel files to $(prefix)$(libdir_name) if needed
install-data-hook:
	rm  $(DESTDIR)$(rootlibdir)/libudev.la
	if test "$(prefix)" != "$(exec_prefix)"; then \
		mkdir -p $(DESTDIR)$(prefix)/$(libdir_name); \
		mv $(DESTDIR)$(rootlibdir)/libudev.a $(DESTDIR)$(prefix)/$(libdir_name)/; \
		so_img_name=$$(readlink $(DESTDIR)$(rootlibdir)/libudev.so); \
		rm $(DESTDIR)$(rootlibdir)/libudev.so; \
		so_img_rel_target_prefix=$$(echo $(prefix)/$(libdir_name) | sed 's,\(^/\|\)[^/][^/]*,..,g'); \
		ln -sf  $$so_img_rel_target_prefix$(exec_prefix)/$(libdir_name)/$$so_img_name \
			$(DESTDIR)$(prefix)/$(libdir_name)/libudev.so; \
	fi

uninstall-hook:
	rm -f $(DESTDIR)$(prefix)/$(libdir_name)/libudev.a
	rm -f $(DESTDIR)$(prefix)/$(libdir_name)/libudev.so*
