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

# Set the following to control the use of syslog
# Set it to `false' to remove all logging
USE_LOG = true

# Set the following to `true' to log the debug
# and make a unstripped, unoptimized  binary.
# Leave this set to `false' for production use.
DEBUG = false

# Set the following to `true' to make udev emit a D-BUS signal when a
# new node is created.
USE_DBUS = false


ROOT =		udev
DAEMON =	udevd
SENDER =	udevsend
HELPER =	udevinfo
TESTER =	udevtest
VERSION =	019_bk
INSTALL_DIR =	/usr/local/bin
RELEASE_NAME =	$(ROOT)-$(VERSION)
LOCAL_CFG_DIR =	etc/udev
HOTPLUG_EXEC =	$(ROOT)

DESTDIR =

KERNEL_DIR = /lib/modules/${shell uname -r}/build

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

# set up PWD so that older versions of make will work with our build.
PWD = $(shell pwd)

# If you are running a cross compiler, you may want to set this
# to something more interesting, like "arm-linux-".  If you want
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
WARNINGS := -Wall 

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

ifeq ($(strip $(USE_LOG)),true)
	CFLAGS  += -DLOG
endif

# if DEBUG is enabled, then we do not strip or optimize
ifeq ($(strip $(DEBUG)),true)
	CFLAGS  += -O1 -g -DDEBUG -D_GNU_SOURCE
	LDFLAGS += -Wl,-warn-common
	STRIPCMD = /bin/true -Since_we_are_debugging
else
	CFLAGS  += $(OPTIMIZATION) -fomit-frame-pointer -D_GNU_SOURCE
	LDFLAGS += -s -Wl,-warn-common
	STRIPCMD = $(STRIP) -s --remove-section=.note --remove-section=.comment
endif

# If we are using our version of klibc, then we need to build, link it, and then
# link udev against it statically.
# Otherwise, use glibc and link dynamically.
ifeq ($(strip $(USE_KLIBC)),true)
	KLIBC_BASE	= $(PWD)/klibc
	KLIBC_DIR	= $(KLIBC_BASE)/klibc
	INCLUDE_DIR	:= $(KLIBC_DIR)/include
	LINUX_INCLUDE_DIR	:= $(KERNEL_DIR)/include
#	LINUX_INCLUDE_DIR	:= $(KLIBC_BASE)/linux/include
	include $(KLIBC_DIR)/arch/$(ARCH)/MCONFIG
	# arch specific objects
	ARCH_LIB_OBJS =	\
			$(KLIBC_DIR)/libc.a


	CRT0 = $(KLIBC_DIR)/crt0.o
	LIBC =	$(ARCH_LIB_OBJS) $(LIB_OBJS) $(CRT0)
	CFLAGS += $(WARNINGS) -nostdinc			\
		-D__KLIBC__ -fno-builtin-printf		\
		-I$(INCLUDE_DIR)			\
		-I$(KLIBC_DIR)/arch/$(ARCH)/include	\
		-I$(INCLUDE_DIR)/bits$(BITSIZE)		\
		-I$(GCCINCDIR)				\
		-I$(LINUX_INCLUDE_DIR)
	LIB_OBJS =
	LDFLAGS = --static --nostdlib -nostartfiles -nodefaultlibs
else
	WARNINGS += -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
	CRT0 =
	LIBC = 
	CFLAGS += $(WARNINGS) -I$(GCCINCDIR)
	LIB_OBJS = -lc
	LDFLAGS =
endif

CFLAGS += -I$(PWD)/libsysfs

all: $(ROOT) $(SENDER) $(DAEMON) $(HELPER) $(TESTER)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) \
			LD="$(LD)" \
			SYSFS="$(SYSFS)" \
			KERNEL_DIR="$(KERNEL_DIR)" \
			-C $$target $@ ; \
	done ; \

$(ARCH_LIB_OBJS) : $(CRT0)

$(CRT0):
	$(MAKE) -C klibc KERNEL_DIR=$(KERNEL_DIR)

TDB =	tdb/tdb.o	\
	tdb/spinlock.o

SYSFS =	$(PWD)/libsysfs/sysfs_bus.o	\
	$(PWD)/libsysfs/sysfs_class.o	\
	$(PWD)/libsysfs/sysfs_device.o	\
	$(PWD)/libsysfs/sysfs_dir.o	\
	$(PWD)/libsysfs/sysfs_driver.o	\
	$(PWD)/libsysfs/sysfs_utils.o	\
	$(PWD)/libsysfs/dlist.o

OBJS =	udev_config.o	\
	udev-add.o	\
	udev-remove.o	\
	udevdb.o	\
	namedev.o	\
	namedev_parse.o	\
	$(SYSFS)	\
	$(TDB)

HEADERS =	udev.h		\
		namedev.h	\
		udev_version.h	\
		udev_dbus.h	\
		udevdb.h	\
		klibc_fixups.h	\
		logging.h	\
		list.h

ifeq ($(strip $(USE_KLIBC)),true)
	OBJS += klibc_fixups.o
endif

ifeq ($(USE_DBUS), true)
	CFLAGS += -DUSE_DBUS
	CFLAGS += $(shell pkg-config --cflags dbus-1)
	LDFLAGS += $(shell pkg-config --libs dbus-1)
	OBJS += udev_dbus.o
endif

# if USE_SELINUX is enabled, then we do not strip or optimize
ifeq ($(strip $(USE_SELINUX)),true)
	CFLAGS  += -DUSE_SELINUX
	OBJS += udev_selinux.o
	LIB_OBJS += -lselinux
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
	@echo \#define UDEV_LOG_DEFAULT \"yes\" >> $@
	@echo \#define UDEV_BIN		\"$(DESTDIR)$(sbindir)/udev\" >> $@
	@echo \#define UDEVD_BIN	\"$(DESTDIR)$(sbindir)/udevd\" >> $@

# config files automatically generated
GEN_CONFIGS =	$(LOCAL_CFG_DIR)/udev.conf

# Rules on how to create the generated config files
$(LOCAL_CFG_DIR)/udev.conf:
	sed -e "s:@udevdir@:$(udevdir):" < $(LOCAL_CFG_DIR)/udev.conf.in > $@


$(OBJS): $(GEN_HEADERS)
$(ROOT).o: $(GEN_HEADERS)
$(TESTER).o: $(GEN_HEADERS)
$(HELPER).o: $(GEN_HEADERS)
$(DAEMON).o: $(GEN_HEADERS)
$(SENDER).o: $(GEN_HEADERS)

$(ROOT): $(ROOT).o $(OBJS) $(HEADERS) $(LIBC)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) udev.o $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(STRIPCMD) $@

$(TESTER): $(TESTER).o $(OBJS) $(HEADERS) $(LIBC)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) udevtest.o $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(STRIPCMD) $@

$(HELPER): $(HELPER).o $(OBJS) $(HEADERS) $(LIBC)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) udevinfo.o udev_config.o udevdb.o $(SYSFS) $(TDB) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(STRIPCMD) $@

$(DAEMON): $(DAEMON).o udevd.h $(LIBC)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) udevd.o $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(STRIPCMD) $@

$(SENDER): $(SENDER).o udevd.h $(LIBC)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) udevsend.o $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(STRIPCMD) $@

clean:
	-find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print \
	 | xargs rm -f 
	-rm -f core $(ROOT) $(GEN_HEADERS) $(GEN_CONFIGS) $(HELPER) $(DAEMON) $(SENDER) $(TESTER)
	$(MAKE) -C klibc clean
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

DISTFILES = $(shell find . \( -not -name '.' \) -print | grep -v -e CVS -e "\.tar\.gz$" -e "\/\." -e releases -e BitKeeper -e SCCS -e "\.tdb$" -e test/sys | sort )
DISTDIR := $(RELEASE_NAME)
srcdir = .
release: clean
	-rm -rf $(DISTDIR)
	mkdir $(DISTDIR)
	chmod 777 $(DISTDIR)
	bk export $(DISTDIR)
	tar -c $(DISTDIR) | gzip -9 > $(RELEASE_NAME).tar.gz
	rm -rf $(DISTDIR)
	@echo "$(RELEASE_NAME).tar.gz created"


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
	$(INSTALL_DATA) etc/dbus-1/system.d/udev_sysbus_policy.conf $(DESTDIR)$(dbusdir)

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
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)udev.rules ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.rules $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.rules $(DESTDIR)$(configdir); \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)udev.permissions ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.permissions $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.permissions $(DESTDIR)$(configdir); \
	fi

install: install-config install-dbus-policy all
	$(INSTALL) -d $(DESTDIR)$(udevdir)
	$(INSTALL) -d $(DESTDIR)$(hotplugdir)
	$(INSTALL_PROGRAM) -D $(ROOT) $(DESTDIR)$(sbindir)/$(ROOT)
	$(INSTALL_PROGRAM) -D $(DAEMON) $(DESTDIR)$(sbindir)/$(DAEMON)
	$(INSTALL_PROGRAM) -D $(SENDER) $(DESTDIR)$(sbindir)/$(SENDER)
	$(INSTALL_PROGRAM) -D $(HELPER) $(DESTDIR)$(sbindir)/$(HELPER)
	$(INSTALL_PROGRAM) -D $(TESTER) $(DESTDIR)$(sbindir)/$(TESTER)
	@if [ "x$(USE_LSB)" = "xtrue" ]; then \
		$(INSTALL_PROGRAM) -D etc/init.d/udev.init.LSB $(DESTDIR)$(initdir)/udev; \
		ln -s $(DESTDIR)$(initdir)/udev $(sbindir)/rcudev; \
	else \
		$(INSTALL_PROGRAM) -D etc/init.d/udev $(DESTDIR)$(initdir)/udev; \
	fi
	$(INSTALL_DATA) -D udev.8 $(DESTDIR)$(mandir)/man8/udev.8
	$(INSTALL_DATA) -D udevinfo.8 $(DESTDIR)$(mandir)/man8/udevinfo.8
	$(INSTALL_DATA) -D udevd.8 $(DESTDIR)$(mandir)/man8/udevd.8
	- ln -f -s udevd.8 $(DESTDIR)$(mandir)/man8/udevsend.8
	- ln -f -s $(sbindir)/$(SENDER) $(DESTDIR)$(hotplugdir)/$(ROOT).hotplug
ifndef DESTDIR
	- killall udevd
	- rm -f $(udevdir)/.udev.tdb
endif
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
	- rm $(mandir)/man8/udevinfo.8
	- rm $(sbindir)/$(ROOT)
	- rm $(sbindir)/$(DAEMON)
	- rm $(sbindir)/$(SENDER)
	- rm $(sbindir)/$(HELPER)
	- rmdir $(hotplugdir)
	- rmdir $(configdir)
	- rm $(udevdir)/.udev.tdb
	- rmdir $(udevdir)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \
