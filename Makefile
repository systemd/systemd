# Makefile for udev
#
# Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
# Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
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

# Set this to make use of syslog.
USE_LOG = true

# Set this to compile-in development debug messages. Pass UDEV_LOG="debug"
# to the executed binary or set the value in the udev configuration file to
# let udev print the debug messages to syslog.
DEBUG = false

# Set this to include Security-Enhanced Linux support.
USE_SELINUX = false

# Set this to comile with klibc instead of glibc.
USE_KLIBC = false

# Set this to create statically linked binaries.
USE_STATIC = false

# To build any of the extras programs, run with:
# 	make EXTRAS="extras/a extras/b"
EXTRAS=

# make the build silent. Set this to something else to make it noisy again.
V=false

ROOT =		udev
DAEMON =	udevd
SENDER =	udevsend
COMPILE =	udevrulescompile
INITSENDER =	udevinitsend
RECORDER =	udeveventrecorder
CONTROL =	udevcontrol
INFO =		udevinfo
TESTER =	udevtest
STARTER =	udevstart
VERSION =	059
RELEASE_NAME =	$(ROOT)-$(VERSION)
LOCAL_CFG_DIR =	etc/udev
DESTDIR =
KERNEL_DIR = /lib/modules/${shell uname -r}/build

# override this to make udev look in a different location for it's config files
prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
usrbindir =	${exec_prefix}/usr/bin
mandir =	${prefix}/usr/share/man
configdir =	${etcdir}/udev
srcdir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}

# place to put our device nodes
udevdir =	${prefix}/udev
udevdb =	${udevdir}/.udevdb

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

export CROSS CC AR STRIP RANLIB CFLAGS LDFLAGS LIB_OBJS

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

# check if compiler option is supported
cc-supports = ${shell if $(CC) ${1} -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; fi;}

CFLAGS		+= -Wall -fno-builtin -Wchar-subscripts -Wpointer-arith -Wstrict-prototypes -Wsign-compare
CFLAGS		+= $(call cc-supports,-Wno-pointer-sign)
CFLAGS		+= $(call cc-supports,-Wdeclaration-after-statement)
CFLAGS		+= -pipe
CFLAGS		+= -D_GNU_SOURCE

HEADERS = \
	udev.h			\
	udev_utils.h		\
	udev_rules.h		\
	udev_version.h		\
	udev_db.h		\
	udev_sysfs.h		\
	logging.h		\
	udev_libc_wrapper.h	\
	udev_selinux.h		\
	list.h

SYSFS_OBJS = \
	libsysfs/sysfs_class.o	\
	libsysfs/sysfs_device.o	\
	libsysfs/sysfs_dir.o	\
	libsysfs/sysfs_driver.o	\
	libsysfs/sysfs_utils.o	\
	libsysfs/dlist.o

UDEV_OBJS = \
	udev_utils.o		\
	udev_config.o		\
	udev_add.o		\
	udev_remove.o		\
	udev_sysfs.o		\
	udev_db.o		\
	udev_rules.o		\
	udev_rules_parse.o	\
	udev_libc_wrapper.o

OBJS = \
	udev.a			\
	libsysfs/sysfs.a

SYSFS = $(PWD)/libsysfs/sysfs.a

CFLAGS +=	-I$(PWD)/libsysfs/sysfs \
		-I$(PWD)/libsysfs

ifeq ($(strip $(USE_LOG)),true)
	CFLAGS += -DUSE_LOG
endif

# if DEBUG is enabled, then we do not strip or optimize
ifeq ($(strip $(DEBUG)),true)
	CFLAGS  += -O1 -g -DDEBUG
	LDFLAGS += -Wl
	STRIPCMD = /bin/true -Since_we_are_debugging
else
	CFLAGS  += $(OPTIMIZATION) -fomit-frame-pointer
	LDFLAGS += -s -Wl
	STRIPCMD = $(STRIP) -s --remove-section=.note --remove-section=.comment
endif

# If we are using our version of klibc, then we need to build, link it, and then
# link udev against it statically. Otherwise, use glibc and link dynamically.
ifeq ($(strip $(USE_KLIBC)),true)
	KLIBC_INSTALL	= $(PWD)/klibc/.install
	KLCC		= $(KLIBC_INSTALL)/bin/klcc
	CC		= $(KLCC)
	LD		= $(KLCC)
else
	CFLAGS		+= -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
endif

ifeq ($(strip $(USE_SELINUX)),true)
	UDEV_OBJS += udev_selinux.o
	LIB_OBJS += -lselinux
	CFLAGS += -DUSE_SELINUX
endif

ifeq ($(strip $(USE_STATIC)),true)
	CFLAGS += -DUSE_STATIC
	LDFLAGS += -static
endif

ifeq ($(strip $(V)),false)
	QUIET=@$(PWD)/ccdv
	HOST_PROGS=ccdv
else
	QUIET=
	HOST_PROGS=
endif

# config files automatically generated
GEN_CONFIGS =	$(LOCAL_CFG_DIR)/udev.conf

all: $(ROOT) $(SENDER) $(COMPILE) $(INITSENDER) $(RECORDER) $(CONTROL) \
	$(DAEMON) $(COMPILE) $(INFO) $(TESTER) $(STARTER) $(GEN_CONFIGS) $(KLCC)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) \
			LD="$(LD)" \
			SYSFS="$(SYSFS)" \
			KERNEL_DIR="$(KERNEL_DIR)" \
			QUIET="$(QUIET)" \
			-C $$target $@ ; \
	done ; \

$(KLCC):
	$(MAKE) -j1 -C klibc KRNLSRC=$(KERNEL_DIR) SUBDIRS=klibc TESTS= \
			 SHLIBDIR=$(KLIBC_INSTALL)/lib \
			 INSTALLDIR=$(KLIBC_INSTALL) \
			 bindir=$(KLIBC_INSTALL)/bin \
			 mandir=$(KLIBC_INSTALL)/man all install
	-find $(KLIBC_INSTALL)/include -name SCCS -print| xargs rm -rf

udev.a: $(UDEV_OBJS)
	rm -f $@
	$(QUIET) $(AR) cq $@ $(UDEV_OBJS)
	$(QUIET) $(RANLIB) $@

libsysfs/sysfs.a: $(SYSFS_OBJS)
	rm -f $@
	$(QUIET) $(AR) cq $@ $(SYSFS_OBJS)
	$(QUIET) $(RANLIB) $@

# header files automatically generated
GEN_HEADERS =	udev_version.h

ccdv:
	@echo "Building ccdv"
	@$(HOSTCC) -O1 ccdv.c -o ccdv

# Rules on how to create the generated header files
udev_version.h:
	@echo "Creating udev_version.h"
	@echo \#define UDEV_VERSION		\"$(VERSION)\" > $@
	@echo \#define UDEV_ROOT		\"$(udevdir)\" >> $@
	@echo \#define UDEV_DB			\"$(udevdb)\" >> $@
	@echo \#define UDEV_CONFIG_DIR		\"$(configdir)\" >> $@
	@echo \#define UDEV_CONFIG_FILE		\"$(configdir)/udev.conf\" >> $@
	@echo \#define UDEV_RULES_FILE		\"$(configdir)/rules.d\" >> $@
	@echo \#define UDEV_BIN			\"$(sbindir)/udev\" >> $@
	@echo \#define UDEVD_BIN		\"$(sbindir)/udevd\" >> $@

# Rules on how to create the generated config files
$(LOCAL_CFG_DIR)/udev.conf:
	sed -e "s:@udevdir@:$(udevdir):" -e "s:@configdir@:$(configdir):" < $(LOCAL_CFG_DIR)/udev.conf.in > $@

GEN_MANPAGES   = udev.8
GEN_MANPAGESIN = udev.8.in
# Rules on how to create the man pages
$(GEN_MANPAGES): $(GEN_MANPAGESIN)
	sed -e "s:@udevdir@:$(udevdir):" < $@.in > $@

$(UDEV_OBJS): $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(SYSFS_OBJS): $(HEADERS) $(HOST_PROGS) $(KLCC)
$(OBJS): $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(ROOT).o: $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(TESTER).o: $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(INFO).o: $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(DAEMON).o: $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(SENDER).o: $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(COMPILE).o: $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(INITSENDER).o: $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(RECORDER).o: $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(CONTROL).o: $(HEADERS) $( $(HEADERS)GEN_HEADERS) $(HOST_PROGS) $(KLCC)
$(STARTER).o: $(HEADERS) $(GEN_HEADERS) $(HOST_PROGS) $(KLCC)

$(ROOT): $(KLCC) $(ROOT).o $(OBJS) $(HEADERS) $(GEN_MANPAGES)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(ROOT).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(TESTER): $(KLCC) $(TESTER).o $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(TESTER).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(INFO): $(KLCC) $(INFO).o $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(INFO).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(DAEMON): $(KLCC) $(DAEMON).o $(OBJS) udevd.h
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(DAEMON).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(SENDER): $(KLCC) $(SENDER).o $(OBJS) udevd.h
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(SENDER).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(COMPILE): $(KLCC) $(COMPILE).o $(OBJS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(COMPILE).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(INITSENDER): $(KLCC) $(INITSENDER).o $(OBJS) udevd.h
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(INITSENDER).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(RECORDER): $(KLCC) $(RECORDER).o $(OBJS) udevd.h
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(RECORDER).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(CONTROL): $(KLCC) $(CONTROL).o $(OBJS) udevd.h
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CONTROL).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(STARTER): $(KLCC) $(STARTER).o $(OBJS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(STARTER).o $(OBJS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

.c.o:
	$(QUIET) $(CC) $(CFLAGS) -c -o $@ $<

clean:
	-find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print \
	 | xargs rm -f 
	-rm -f core $(ROOT) $(GEN_HEADERS) $(GEN_CONFIGS) $(GEN_MANPAGES) $(INFO) $(DAEMON) \
	 $(SENDER) $(COMPILE) $(INITSENDER) $(RECORDER) $(CONTROL) $(TESTER) $(STARTER)
	-rm -f ccdv
	$(MAKE) -C klibc SUBDIRS=klibc clean
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

spotless: clean
	$(MAKE) -C klibc SUBDIRS=klibc spotless
	rm -rf klibc/.install

release: spotless
	git-tar-tree HEAD $(RELEASE_NAME) | gzip -9v > $(RELEASE_NAME).tar.gz
	@echo "$(RELEASE_NAME).tar.gz created"

install-config:
	$(INSTALL) -d $(DESTDIR)$(configdir)/rules.d
	@if [ ! -r $(DESTDIR)$(configdir)/udev.conf ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)/rules.d/50-udev.rules ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.rules $(DESTDIR)$(configdir)/rules.d/50-udev.rules; \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.rules $(DESTDIR)$(configdir)/rules.d/50-udev.rules; \
	fi

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

install: install-config install-man all
	$(INSTALL) -d $(DESTDIR)$(udevdir)
	$(INSTALL_PROGRAM) -D $(ROOT) $(DESTDIR)$(sbindir)/$(ROOT)
	$(INSTALL_PROGRAM) -D $(DAEMON) $(DESTDIR)$(sbindir)/$(DAEMON)
	$(INSTALL_PROGRAM) -D $(SENDER) $(DESTDIR)$(sbindir)/$(SENDER)
	$(INSTALL_PROGRAM) -D $(CONTROL) $(DESTDIR)$(sbindir)/$(CONTROL)
	$(INSTALL_PROGRAM) -D $(INFO) $(DESTDIR)$(usrbindir)/$(INFO)
	$(INSTALL_PROGRAM) -D $(TESTER) $(DESTDIR)$(usrbindir)/$(TESTER)
	$(INSTALL_PROGRAM) -D $(STARTER) $(DESTDIR)$(sbindir)/$(STARTER)
ifndef DESTDIR
	- killall $(DAEMON)
	- $(sbindir)/$(DAEMON) --daemon
	- rm -rf $(udevdb)
endif
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

uninstall: uninstall-man
	- rm $(configdir)/rules.d/50-udev.rules
	- rm $(configdir)/udev.conf
	- rmdir $(configdir)/rules.d
	- rmdir $(configdir)
	- rm $(sbindir)/$(ROOT)
	- rm $(sbindir)/$(DAEMON)
	- rm $(sbindir)/$(SENDER)
	- rm $(sbindir)/$(INITSENDER)
	- rm $(sbindir)/$(RECORDER)
	- rm $(sbindir)/$(CONTROL)
	- rm $(sbindir)/$(STARTER)
	- rm $(usrbindir)/$(INFO)
	- rm $(usrbindir)/$(TESTER)
	- rm -rf $(udevdb)
	- rmdir $(udevdir)
	- killall $(DAEMON)
	@extras="$(EXTRAS)" ; for target in $$extras ; do \
		echo $$target ; \
		$(MAKE) prefix=$(prefix) LD="$(LD)" SYSFS="$(SYSFS)" \
			-C $$target $@ ; \
	done ; \

test: all
	@ cd test && ./udev-test.pl
	@ cd test && ./udevstart-test.pl
