# Makefile for udev
#
# Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
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

# Set this to compile with Security-Enhanced Linux support.
USE_SELINUX = false

ROOT =		udev
DAEMON =	udevd
SENDER =	udevsend
INFO =		udevinfo
TESTER =	udevtest
STARTER =	udevstart
WAIT =		wait_for_sysfs
VERSION =	040
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
usrbindir =	${exec_prefix}/usr/bin
mandir =	${prefix}/usr/share/man
hotplugdir =	${etcdir}/hotplug.d/default
configdir =	${etcdir}/udev
initdir = 	${etcdir}/init.d
dev_ddir =	${etcdir}/dev.d
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

# make the build silent (well, at least the udev part)  Set this
# to something else to make it noisy again.
V=false

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
HOSTCC = gcc

export CROSS CC AR STRIP RANLIB CFLAGS LDFLAGS LIB_OBJS ARCH_LIB_OBJS CRT0

# code taken from uClibc to determine the current arch
ARCH := ${shell $(CC) -dumpmachine | sed -e s'/-.*//' -e 's/i.86/i386/' -e 's/sparc.*/sparc/' \
	-e 's/arm.*/arm/g' -e 's/m68k.*/m68k/' -e 's/powerpc/ppc/g'}

# code taken from uClibc to determine the gcc include dir
GCCINCDIR := ${shell LC_ALL=C $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}

# code taken from uClibc to determine the libgcc.a filename
GCC_LIB := $(shell $(CC) -print-libgcc-file-name )

# use '-Os' optimization if available, else use -O2
OPTIMIZATION := ${shell if $(CC) -Os -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
		then echo "-Os"; else echo "-O2" ; fi}

# add -Wredundant-decls when libsysfs gets cleaned up
WARNINGS := -Wall 

CFLAGS := -pipe

# set up the proper tdb spinlock code if we can
ifeq ($(strip $(ARCH)),i386)
	CFLAGS += -DUSE_SPINLOCKS -DINTEL_SPINLOCKS
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
	INCLUDE_DIR	:= $(KLIBC_BASE)/include
	LINUX_INCLUDE_DIR	:= $(KERNEL_DIR)/include
	include $(KLIBC_DIR)/arch/$(ARCH)/MCONFIG
	# arch specific objects
	ARCH_LIB_OBJS =	\
			$(KLIBC_DIR)/libc.a


	CRT0 = $(KLIBC_DIR)/crt0.o
	LIBC = $(ARCH_LIB_OBJS) $(LIB_OBJS) $(CRT0)
	CFLAGS += $(WARNINGS) -nostdinc			\
		$(OPTFLAGS)				\
		-D__KLIBC__ -fno-builtin-printf		\
		-I$(INCLUDE_DIR)			\
		-I$(INCLUDE_DIR)/arch/$(ARCH)		\
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

ifeq ($(strip $(USE_SELINUX)),true)
	CFLAGS += -DUSE_SELINUX
	LIB_OBJS += -lselinux
endif

CFLAGS += -I$(PWD)/libsysfs

# config files automatically generated
GEN_CONFIGS =	$(LOCAL_CFG_DIR)/udev.conf

all: $(ROOT) $(SENDER) $(DAEMON) $(INFO) $(TESTER) $(WAIT) $(GEN_CONFIGS)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) \
			LD="$(LD)" \
			SYSFS="$(SYSFS)" \
			KERNEL_DIR="$(KERNEL_DIR)" \
			QUIET="@$(PWD)/ccdv" \
			-C $$target $@ ; \
	done ; \

$(ARCH_LIB_OBJS) : $(CRT0)

$(CRT0):
	@if [ ! -r klibc/linux ]; then \
		ln -f -s $(KERNEL_DIR) klibc/linux; \
	fi
	$(MAKE) -C klibc SUBDIRS=klibc

TDB =	tdb/tdb.o	\
	tdb/spinlock.o

SYSFS =	$(PWD)/libsysfs/sysfs_bus.o	\
	$(PWD)/libsysfs/sysfs_class.o	\
	$(PWD)/libsysfs/sysfs_device.o	\
	$(PWD)/libsysfs/sysfs_dir.o	\
	$(PWD)/libsysfs/sysfs_driver.o	\
	$(PWD)/libsysfs/sysfs_utils.o	\
	$(PWD)/libsysfs/dlist.o

OBJS =	udev_lib.o	\
	udev_config.o	\
	udev_add.o	\
	udev_remove.o	\
	udevdb.o	\
	namedev.o	\
	namedev_parse.o	\
	dev_d.o		\
	$(SYSFS)	\
	$(TDB)

HEADERS =	udev.h		\
		udev_lib.h	\
		namedev.h	\
		udev_version.h	\
		udevdb.h	\
		klibc_fixups.h	\
		logging.h	\
		selinux.h	\
		list.h

ifeq ($(strip $(USE_KLIBC)),true)
	OBJS += klibc_fixups.o
	KLIBC_FIXUP = klibc_fixups.o
endif

ifeq ($(strip $(V)),false)
	QUIET=@./ccdv
	HOST_PROGS=ccdv
else
	QUIET=
	HOST_PROGS=
endif

# header files automatically generated
GEN_HEADERS =	udev_version.h

ccdv:
	@echo "Building ccdv"
	@$(HOSTCC) -O1 ccdv.c -o ccdv

# Rules on how to create the generated header files
udev_version.h:
	@echo "Creating udev_version.h"
	@echo \#define UDEV_VERSION		\"$(VERSION)\" > $@
	@echo \#define UDEV_ROOT		\"$(udevdir)/\" >> $@
	@echo \#define UDEV_DB			\"$(udevdir)/.udev.tdb\" >> $@
	@echo \#define UDEV_CONFIG_DIR		\"$(configdir)\" >> $@
	@echo \#define UDEV_CONFIG_FILE		\"$(configdir)/udev.conf\" >> $@
	@echo \#define UDEV_RULES_FILE		\"$(configdir)/rules.d\" >> $@
	@echo \#define UDEV_PERMISSION_FILE	\"$(configdir)/permissions.d\" >> $@
	@echo \#define UDEV_LOG_DEFAULT 	\"yes\" >> $@
	@echo \#define UDEV_BIN			\"$(DESTDIR)$(sbindir)/udev\" >> $@
	@echo \#define UDEVD_BIN		\"$(DESTDIR)$(sbindir)/udevd\" >> $@

# Rules on how to create the generated config files
$(LOCAL_CFG_DIR)/udev.conf:
	sed -e "s:@udevdir@:$(udevdir):" -e "s:@configdir@:$(configdir):" < $(LOCAL_CFG_DIR)/udev.conf.in > $@

GEN_MANPAGES   = udev.8
GEN_MANPAGESIN = udev.8.in
# Rules on how to create the man pages
$(GEN_MANPAGES): $(GEN_MANPAGESIN)
	sed -e "s:@udevdir@:$(udevdir):" < $@.in > $@

$(OBJS): $(GEN_HEADERS) $(HOST_PROGS)
$(ROOT).o: $(GEN_HEADERS) $(HOST_PROGS)
$(TESTER).o: $(GEN_HEADERS) $(HOST_PROGS)
$(INFO).o: $(GEN_HEADERS) $(HOST_PROGS)
$(DAEMON).o: $(GEN_HEADERS) $(HOST_PROGS)
$(SENDER).o: $(GEN_HEADERS) $(HOST_PROGS)
$(STARTER).o: $(GEN_HEADERS) $(HOST_PROGS)
$(WAIT).o: $(GEN_HEADERS) $(HOST_PROGS)

$(ROOT): $(LIBC) $(ROOT).o $(STARTER).o $(OBJS) $(HEADERS) $(GEN_MANPAGES)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) udev.o udevstart.o $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(TESTER): $(LIBC) $(TESTER).o $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) udevtest.o $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(INFO): $(LIBC) $(INFO).o $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) udevinfo.o udev_lib.o udev_config.o udevdb.o $(SYSFS) $(TDB) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(DAEMON): $(LIBC) $(DAEMON).o $(OBJS) udevd.h
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) udevd.o udev_lib.o $(KLIBC_FIXUP) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(SENDER): $(LIBC) $(SENDER).o $(OBJS) udevd.h
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) udevsend.o udev_lib.o $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(WAIT): $(WAIT).o $(OBJS) $(HEADERS) $(LIBC)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) $(WAIT).o $(SYSFS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

#.c.o:
#	$(CC) $(CFLAGS) $(DEFS) $(CPPFLAGS) -c -o $@ $<
.c.o:
	$(QUIET) $(CC) $(CFLAGS) -c -o $@ $<


clean:
	-find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print \
	 | xargs rm -f 
	-rm -f core $(ROOT) $(GEN_HEADERS) $(GEN_CONFIGS) $(GEN_MANPAGES) $(INFO) $(DAEMON) $(SENDER) $(TESTER) $(WAIT)
	-rm -f ccdv
	$(MAKE) -C klibc clean
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

spotless: clean
	$(MAKE) -C klibc spotless
	-rm -f klibc/linux

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


install-initscript: etc/init.d/udev etc/init.d/udev.init.LSB
	@if [ -f /etc/redhat-release ]; then \
		$(INSTALL_DATA) -D etc/init.d/udev $(DESTDIR)$(initdir)/udev; \
	elif [ -f /etc/SuSE-release ]; then \
		$(INSTALL_DATA) -D etc/init.d/udev.init.LSB $(DESTDIR)$(initdir)/udev; \
	fi

install-config:
	$(INSTALL) -d $(DESTDIR)$(configdir)/rules.d
	$(INSTALL) -d $(DESTDIR)$(configdir)/permissions.d
	@if [ ! -r $(DESTDIR)$(configdir)/udev.conf ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)/rules.d/50-udev.rules ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.rules $(DESTDIR)$(configdir)/rules.d/50-udev.rules; \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.rules $(DESTDIR)$(configdir)/rules.d/50-udev.rules; \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)/permissions.d/50-udev.permissions ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.permissions $(DESTDIR)$(configdir)/permissions.d/50-udev.permissions; \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.permissions $(DESTDIR)$(configdir)/permissions.d/50-udev.permissions; \
	fi

install-dev.d:
	$(INSTALL) -d $(DESTDIR)$(dev_ddir)/default
	$(INSTALL_PROGRAM) -D etc/dev.d/net/hotplug.dev $(DESTDIR)$(dev_ddir)/net/hotplug.dev

uninstall-dev.d:
	- rm $(dev_ddir)/net/hotplug.dev
	- rmdir $(dev_ddir)/net
	- rmdir $(dev_ddir)/default
	- rmdir $(dev_ddir)

install-man:
	$(INSTALL_DATA) -D udev.8 $(DESTDIR)$(mandir)/man8/udev.8
	$(INSTALL_DATA) -D udevinfo.8 $(DESTDIR)$(mandir)/man8/udevinfo.8
	$(INSTALL_DATA) -D udevtest.8 $(DESTDIR)$(mandir)/man8/udevtest.8
	$(INSTALL_DATA) -D udevstart.8 $(DESTDIR)$(mandir)/man8/udevstart.8
	$(INSTALL_DATA) -D udevd.8 $(DESTDIR)$(mandir)/man8/udevd.8
	- ln -f -s udevd.8 $(DESTDIR)$(mandir)/man8/udevsend.8

uninstall-man:
	- rm $(mandir)/man8/udev.8
	- rm $(mandir)/man8/udevinfo.8
	- rm $(mandir)/man8/udevtest.8
	- rm $(mandir)/man8/udevstart.8
	- rm $(mandir)/man8/udevd.8
	- rm $(mandir)/man8/udevsend.8

install: install-initscript install-config install-man install-dev.d all
	$(INSTALL) -d $(DESTDIR)$(udevdir)
	$(INSTALL) -d $(DESTDIR)$(hotplugdir)
	$(INSTALL_PROGRAM) -D $(ROOT) $(DESTDIR)$(sbindir)/$(ROOT)
	$(INSTALL_PROGRAM) -D $(DAEMON) $(DESTDIR)$(sbindir)/$(DAEMON)
	$(INSTALL_PROGRAM) -D $(SENDER) $(DESTDIR)$(sbindir)/$(SENDER)
	$(INSTALL_PROGRAM) -D $(INFO) $(DESTDIR)$(usrbindir)/$(INFO)
	$(INSTALL_PROGRAM) -D $(TESTER) $(DESTDIR)$(usrbindir)/$(TESTER)
	$(INSTALL_PROGRAM) -D $(WAIT) $(DESTDIR)$(sbindir)/$(WAIT)
	- ln -f -s $(sbindir)/udev $(DESTDIR)$(sbindir)/$(STARTER)
	- ln -f -s $(sbindir)/$(SENDER) $(DESTDIR)$(hotplugdir)/10-udev.hotplug
	- ln -f -s $(sbindir)/$(WAIT) $(DESTDIR)$(hotplugdir)/05-wait_for_sysfs.hotplug
ifndef DESTDIR
	- killall udevd
	- rm -f $(udevdir)/.udev.tdb
endif
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

uninstall: uninstall-man uninstall-dev.d
	- rm $(hotplugdir)/10-udev.hotplug
	- rm $(hotplugdir)/05-wait_for_sysfs.hotplug
	- rm $(configdir)/rules.d/50-udev.rules
	- rm $(configdir)/permissions.d/50-udev.permissions
	- rm $(configdir)/udev.conf
	- rmdir $(configdir)/rules.d
	- rmdir $(configdir)/permissions.d
	- rmdir $(configdir)
	- rm $(initdir)/udev
	- rm $(sbindir)/$(ROOT)
	- rm $(sbindir)/$(DAEMON)
	- rm $(sbindir)/$(SENDER)
	- rm $(sbindir)/$(STARTER)
	- rm $(usrbindir)/$(INFO)
	- rm $(usrbindir)/$(TESTER)
	- rm $(usrbindir)/$(WAIT)
	- rmdir $(hotplugdir)
	- rm $(udevdir)/.udev.tdb
	- rmdir $(udevdir)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \
