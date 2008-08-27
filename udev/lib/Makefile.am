AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

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
	../list.h \
	../udev.h \
	../udev_utils.c \
	../udev_utils_string.c \
	../udev_utils_file.c \
	../udev_sysfs.c \
	../udev_node.c \
	../udev_device.c \
	../udev_config.c \
	../udev_rules.c \
	../udev_rules_parse.c \
	../udev_db.c \
	../udev_sysdeps.c

libudev_la_LDFLAGS = \
	-version-info $(LIBUDEV_LT_CURRENT):$(LIBUDEV_LT_REVISION):$(LIBUDEV_LT_AGE) \
	-export-symbols $(top_srcdir)/udev/lib/exported_symbols

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
