include $(top_srcdir)/Makefile.am.inc

# putting ‘.’ first causes prefix ordering of directories
SUBDIRS = \
	. \
	docs

AM_CPPFLAGS += \
	-I$(top_builddir)/extras \
	-I$(top_srcdir)/extras \
	-I$(top_builddir)/extras/gudev \
	-I$(top_srcdir)/extras/gudev \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
	-D_GUDEV_COMPILATION \
	-DG_UDEV_API_IS_SUBJECT_TO_CHANGE \
	-DG_LOG_DOMAIN=\"GUdev\"

BUILT_SOURCES = \
	gudevmarshal.h		gudevmarshal.c \
	gudevenumtypes.h	gudevenumtypes.c

gudevmarshal.h: gudevmarshal.list
	glib-genmarshal $< --prefix=g_udev_marshal --header > $@

gudevmarshal.c: gudevmarshal.list
	echo "#include \"gudevmarshal.h\"" > $@ && \
	glib-genmarshal $< --prefix=g_udev_marshal --body >> $@

gudevenumtypes.h: $(srcdir)/gudevenumtypes.h.template gudevenums.h
	glib-mkenums --template $(srcdir)/gudevenumtypes.h.template gudevenums.h > \
	    gudevenumtypes.h.tmp && mv gudevenumtypes.h.tmp gudevenumtypes.h

gudevenumtypes.c: $(srcdir)/gudevenumtypes.c.template gudevenums.h
	glib-mkenums --template $(srcdir)/gudevenumtypes.c.template gudevenums.h > \
	    gudevenumtypes.c.tmp && mv gudevenumtypes.c.tmp gudevenumtypes.c

lib_LTLIBRARIES = libgudev-1.0.la

libgudev_1_0_includedir=$(includedir)/gudev-1.0/gudev
libgudev_1_0_include_HEADERS = \
	gudev.h \
	gudevenums.h \
	gudevenumtypes.h \
	gudevtypes.h \
	gudevclient.h \
	gudevdevice.h

libgudev_1_0_la_SOURCES = \
	gudevenums.h \
	gudevenumtypes.h	gudevenumtypes.h\
	gudevtypes.h \
	gudevclient.h		gudevclient.c \
	gudevdevice.h		gudevdevice.c \
	gudevprivate.h \
	$(BUILT_SOURCES)

libgudev_1_0_la_CFLAGS = $(GLIB_CFLAGS)

libgudev_1_0_la_LIBADD = $(top_builddir)/libudev/libudev.la $(GLIB_LIBS)

LT_CURRENT=0
LT_REVISION=1
LT_AGE=0
libgudev_1_0_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-export-dynamic -no-undefined \
	-export-symbols-regex '^g_udev_.*'

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gudev-1.0.pc

EXTRA_DIST = \
	gudev-1.0.pc.in \
	gudevmarshal.list \
	gudevenumtypes.h.template \
	gudevenumtypes.c.template

CLEANFILES = $(BUILT_SOURCES)

if ENABLE_INTROSPECTION
GUdev-1.0.gir: libgudev-1.0.la $(G_IR_SCANNER) Makefile.am
	PKG_CONFIG_PATH=$(top_builddir)/data:$$PKG_CONFIG_PATH \
	$(G_IR_SCANNER) -v \
		--namespace GUdev \
		--nsversion=1.0 \
		--include=GObject-2.0 \
		--library=gudev-1.0 \
		--output $@ \
		--pkg=glib-2.0 \
		--pkg=gobject-2.0 \
		-I$(top_srcdir) \
		-D_GUDEV_COMPILATION \
		-DG_UDEV_API_IS_SUBJECT_TO_CHANGE \
		$(top_srcdir)/extras/gudev/gudev.h \
		$(top_srcdir)/extras/gudev/gudevtypes.h \
		$(top_srcdir)/extras/gudev/gudevenums.h \
		$(top_srcdir)/extras/gudev/gudevenumtypes.h \
		$(top_srcdir)/extras/gudev/gudevclient.h \
		$(top_srcdir)/extras/gudev/gudevdevice.h \
		$(top_srcdir)/extras/gudev/gudevclient.c \
		$(top_srcdir)/extras/gudev/gudevdevice.c

girdir = $(GIRDIR)
gir_DATA = GUdev-1.0.gir

typelibsdir = $(GIRTYPELIBDIR)
typelibs_DATA = GUdev-1.0.typelib

GUdev-1.0.typelib: GUdev-1.0.gir $(G_IR_COMPILER)
	g-ir-compiler GUdev-1.0.gir -o GUdev-1.0.typelib

EXTRA_DIST += GUdev-1.0.gir
CLEANFILES += $(gir_DATA) $(typelibs_DATA)

endif # ENABLE_INTROSPECTION
