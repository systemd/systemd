# Makefile for udev
#
# Copyright (C) 2003  Greg Kroah-Hartman <greg@kroah.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

# Set the following to `true' to make a debuggable build.
# Leave this set to `false' for production use.
DEBUG = false

# Set the following to `true' to make udev emit a D-BUS signal when a
# new node is created.
USE_DBUS = false


ROOT =		udev
VERSION =	010
INSTALL_DIR =	/usr/local/bin
RELEASE_NAME =	$(ROOT)-$(VERSION)

DESTDIR =
# override this to make udev look in a different location for it's config files
prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
mandir =	${prefix}/usr/share/man
hotplugdir =	${etcdir}/hotplug.d/default
dbusdir =	${etcdir}/dbus-1/system.d
configdir =	${etcdir}/udev/
initdir = 	${etcdir}/init.d/
srcdir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}

# To build any of the extras programs, run with:
# 	make EXTRAS="extras/a extras/b" 
EXTRAS=

# place to put our device nodes
udevdir = ${prefix}/udev

# Comment out this line to build with something other 
# than the local version of klibc
#USE_KLIBC = true

# If you are running a cross compiler, you may want to set this
# to something more interesting, like "arm-linux-".  I you want
# to compile vs uClibc, that can be done here as well.
CROSS = #/usr/i386-linux-uclibc/usr/bin/i386-uclibc-
CC = $(CROSS)gcc
LD = $(CROSS)gcc
AR = $(CROSS)ar
STRIP = $(CROSS)strip
RANLIB = $(CROSS)ranlib

export CROSS CC AR STRIP RANLIB CFLAGS LDFLAGS LIB_OBJS ARCH_LIB_OBJS CRT0

# code taken from uClibc to determine the current arch
ARCH := ${shell $(CC) -dumpmachine | sed -e s'/-.*//' -e 's/i.86/i386/' -e 's/sparc.*/sparc/' \
	-e 's/arm.*/arm/g' -e 's/m68k.*/m68k/' -e 's/powerpc/ppc/g'}

# code taken from uClibc to determine the gcc include dir
GCCINCDIR := ${shell $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}

# code taken from uClibc to determine the libgcc.a filename
GCC_LIB := $(shell $(CC) -print-libgcc-file-name )

# use '-Os' optimization if available, else use -O2
OPTIMIZATION := ${shell if $(CC) -Os -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
		then echo "-Os"; else echo "-O2" ; fi}

# add -Wredundant-decls when libsysfs gets cleaned up
WARNINGS := -Wall -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations

# Some nice architecture specific optimizations
ifeq ($(strip $(TARGET_ARCH)),arm)
	OPTIMIZATION+=-fstrict-aliasing
endif
ifeq ($(strip $(TARGET_ARCH)),i386)
	OPTIMIZATION+=-march=i386
	OPTIMIZATION += ${shell if $(CC) -mpreferred-stack-boundary=2 -S -o /dev/null -xc \
		/dev/null >/dev/null 2>&1; then echo "-mpreferred-stack-boundary=2"; fi}
	OPTIMIZATION += ${shell if $(CC) -malign-functions=0 -malign-jumps=0 -S -o /dev/null -xc \
		/dev/null >/dev/null 2>&1; then echo "-malign-functions=0 -malign-jumps=0"; fi}
	CFLAGS+=-pipe
else
	CFLAGS+=-pipe
endif

# if DEBUG is enabled, then we do not strip or optimize
ifeq ($(strip $(DEBUG)),true)
	CFLAGS  += $(WARNINGS) -O1 -g -DDEBUG -D_GNU_SOURCE
	LDFLAGS += -Wl,-warn-common
	STRIPCMD = /bin/true -Since_we_are_debugging
else
	CFLAGS  += $(WARNINGS) $(OPTIMIZATION) -fomit-frame-pointer -D_GNU_SOURCE
	LDFLAGS += -s -Wl,-warn-common
	STRIPCMD = $(STRIP) -s --remove-section=.note --remove-section=.comment
endif

# If we are using our version of klibc, then we need to build and link it.
# Otherwise, use glibc and link statically.
ifeq ($(strip $(USE_KLIBC)),true)
	KLIBC_BASE	= $(PWD)/klibc
	KLIBC_DIR	= $(KLIBC_BASE)/klibc
	INCLUDE_DIR	:= $(KLIBC_DIR)/include
	LINUX_INCLUDE_DIR	:= $(KLIBC_BASE)/linux/include
	include $(KLIBC_DIR)/arch/$(ARCH)/MCONFIG
	# arch specific objects
	ARCH_LIB_OBJS =	\
			$(KLIBC_DIR)/libc.a


	CRT0 = $(KLIBC_DIR)/crt0.o
	LIBC =	$(ARCH_LIB_OBJS) $(LIB_OBJS) $(CRT0)
	CFLAGS += -nostdinc -I$(INCLUDE_DIR) -I$(KLIBC_DIR)/arch/$(ARCH)/include \
		-I$(INCLUDE_DIR)/bits$(BITSIZE) -I$(GCCINCDIR) -I$(LINUX_INCLUDE_DIR) \
		-D__KLIBC__
	LIB_OBJS =
	LDFLAGS = --static --nostdlib -nostartfiles -nodefaultlibs
else
	CRT0 =
	LIBC = 
	CFLAGS += -I$(GCCINCDIR)
	LIB_OBJS = -lc
	LDFLAGS = --static 
endif

CFLAGS += -I$(PWD)/libsysfs

all: $(ROOT)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

$(ROOT): $(LIBC)

$(ARCH_LIB_OBJS) : $(CRT0)

$(CRT0):
	$(MAKE) -C klibc

TDB =	tdb/tdb.o	\
	tdb/spinlock.o

SYSFS =	$(PWD)/libsysfs/sysfs_bus.o	\
	$(PWD)/libsysfs/sysfs_class.o	\
	$(PWD)/libsysfs/sysfs_device.o	\
	$(PWD)/libsysfs/sysfs_dir.o	\
	$(PWD)/libsysfs/sysfs_driver.o	\
	$(PWD)/libsysfs/sysfs_utils.o	\
	$(PWD)/libsysfs/dlist.o

OBJS =	udev.o		\
	udev_config.o	\
	udev-add.o	\
	udev-remove.o	\
	udevdb.o	\
	logging.o	\
	namedev.o	\
	namedev_parse.o	\
	$(SYSFS)	\
	$(TDB)

ifeq ($(strip $(USE_KLIBC)),true)
	OBJS += klibc_fixups.o
endif

ifeq ($(USE_DBUS), true)
	CFLAGS += -DUSE_DBUS
	CFLAGS += $(shell pkg-config --cflags dbus-1)
	LDFLAGS += $(shell pkg-config --libs dbus-1)
	OBJS += udev_dbus.o
endif

# header files automatically generated
GEN_HEADERS =	udev_version.h

# Rules on how to create the generated header files
udev_version.h:
	@echo \#define UDEV_VERSION	\"$(VERSION)\" > $@
	@echo \#define UDEV_ROOT	\"$(udevdir)/\" >> $@
	@echo \#define UDEV_DB		\"$(udevdir)/\.udev.tdb\" >> $@
	@echo \#define UDEV_CONFIG_DIR	\"$(configdir)\" >> $@
	@echo \#define UDEV_CONFIG_FILE	\"$(configdir)\udev.conf\" >> $@
	@echo \#define UDEV_RULES_FILE	\"$(configdir)\udev.rules\" >> $@
	@echo \#define UDEV_PERMISSION_FILE	\"$(configdir)\udev.permissions\" >> $@

# config files automatically generated
GEN_CONFIGS =	udev.conf

# Rules on how to create the generated config files
udev.conf:
	sed -e "s:@udevdir@:$(udevdir):" < udev.conf.in > $@


$(OBJS): $(GEN_HEADERS)

$(ROOT): $(OBJS) udev.h namedev.h
	$(LD) $(LDFLAGS) -o $(ROOT) $(CRT0) $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(STRIPCMD) $(ROOT)

clean:
	-find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print \
	 | xargs rm -f 
	-rm -f core $(ROOT) $(GEN_HEADERS) $(GEN_CONFIGS)
	$(MAKE) -C klibc clean
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

DISTFILES = $(shell find . \( -not -name '.' \) -print | grep -v CVS | grep -v "\.tar\.gz" | grep -v "\/\." | grep -v releases | grep -v BitKeeper | grep -v SCCS | grep -v "\.tdb" | grep -v "test\/sys" | sort )
DISTDIR := $(RELEASE_NAME)
srcdir = .
release: clean
	@echo "--------------------------cut here------------------------"
	@echo "cd .."
	@echo "rm -rf $(DISTDIR)"
	@echo "mkdir $(DISTDIR)"
	@echo "chmod 777 $(DISTDIR)"
	@echo "cp -avr udev/* $(DISTDIR)"
	@echo "tar -c $(DISTDIR) | gzip -9 > $(RELEASE_NAME).tar.gz"
	@echo "rm -rf $(DISTDIR)"
	@echo "--------------------------cut here------------------------"


small_release: $(DISTFILES) clean
#	@echo $(DISTFILES)
	@-rm -rf $(DISTDIR)
	@mkdir $(DISTDIR)
	@-chmod 777 $(DISTDIR)
	@for file in $(DISTFILES); do			\
		if test -d $$file; then			\
		  	mkdir $(DISTDIR)/$$file;	\
		else					\
			cp -p $$file $(DISTDIR)/$$file;	\
		fi;					\
	done
	@tar -c $(DISTDIR) | gzip -9 > $(RELEASE_NAME).tar.gz
	@rm -rf $(DISTDIR)
	@echo "Built $(RELEASE_NAME).tar.gz"


ifeq ($(USE_DBUS), true)
install-dbus-policy:
	$(INSTALL) -d $(DESTDIR)$(dbusdir)
	$(INSTALL_DATA) udev_sysbus_policy.conf $(DESTDIR)$(dbusdir)
uninstall-dbus-policy:
	- rm $(DESTDIR)$(dbusdir)/udev_sysbus_policy.conf
else
install-dbus-policy:
	-
uninstall-dbus-policy:
	-
endif

install-config: $(GEN_CONFIGS)
	$(INSTALL) -d $(DESTDIR)$(configdir)
	@if [ ! -r $(DESTDIR)$(configdir)udev.conf ]; then \
		echo $(INSTALL_DATA) udev.conf $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) udev.conf $(DESTDIR)$(configdir); \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)udev.rules ]; then \
		echo $(INSTALL_DATA) udev.rules $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) udev.rules $(DESTDIR)$(configdir); \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)udev.permissions ]; then \
		echo $(INSTALL_DATA) udev.permissions $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) udev.permissions $(DESTDIR)$(configdir); \
	fi



install: install-config install-dbus-policy all
	$(INSTALL) -d $(DESTDIR)$(udevdir)
	$(INSTALL) -d $(DESTDIR)$(hotplugdir)
	$(INSTALL_PROGRAM) -D $(ROOT) $(DESTDIR)$(sbindir)/$(ROOT)
	$(INSTALL_PROGRAM) -D etc/init.d/udev $(DESTDIR)$(initdir)/udev
	$(INSTALL_DATA) -D udev.8 $(DESTDIR)$(mandir)/man8/udev.8
	- rm -f $(DESTDIR)$(hotplugdir)/udev.hotplug
	- ln -f -s $(sbindir)/$(ROOT) $(DESTDIR)$(hotplugdir)/udev.hotplug
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

uninstall: uninstall-dbus-policy
	- rm $(hotplugdir)/udev.hotplug
	- rm $(configdir)/udev.permissions
	- rm $(configdir)/udev.rules
	- rm $(configdir)/udev.conf
	- rm $(initdir)/udev
	- rm $(mandir)/man8/udev.8
	- rm $(sbindir)/$(ROOT)
	- rmdir $(hotplugdir)
	- rmdir $(configdir)
	- rmdir $(udevdir)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \


