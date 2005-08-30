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

VERSION =	068

# set this to make use of syslog
USE_LOG = true

# compile-in development debug messages
# (export UDEV_LOG="debug" or set udev_log="debug" in udev.conf
#  to print the debug messages to syslog)
DEBUG = false

# include Security-Enhanced Linux support
USE_SELINUX = false

# comile with klibc instead of glibc
USE_KLIBC = false

# set this to create statically linked binaries
USE_STATIC = false

# to build any of the extras programs pass:
#  make EXTRAS="extras/<extra1> extras/<extra2>"
EXTRAS=

# make the build silent. Set this to something else to make it noisy again.
V=false

PROGRAMS = \
	udev				\
	udevd				\
	udevsend			\
	udevrulescompile		\
	udevinitsend			\
	udeveventrecorder		\
	udevcontrol			\
	udevmonitor			\
	udevinfo			\
	udevtest			\
	udevstart

HEADERS = \
	udev.h				\
	udev_utils.h			\
	udev_rules.h			\
	udev_version.h			\
	udev_db.h			\
	udev_sysfs.h			\
	logging.h			\
	udev_libc_wrapper.h		\
	udev_selinux.h			\
	list.h

UDEV_OBJS = \
	udev_event.o			\
	udev_device.o			\
	udev_config.o			\
	udev_add.o			\
	udev_remove.o			\
	udev_sysfs.o			\
	udev_db.o			\
	udev_rules.o			\
	udev_rules_parse.o		\
	udev_utils.o			\
	udev_utils_string.o		\
	udev_utils_file.o		\
	udev_utils_run.o		\
	udev_libc_wrapper.o
LIBUDEV = libudev.a

MAN_PAGES = \
	udev.8				\
	udevmonitor.8			\
	udevd.8				\
	udevsend.8			\
	udevtest.8			\
	udevinfo.8			\
	udevstart.8

SYSFS_OBJS = \
	libsysfs/sysfs_class.o		\
	libsysfs/sysfs_device.o		\
	libsysfs/sysfs_dir.o		\
	libsysfs/sysfs_driver.o		\
	libsysfs/sysfs_utils.o		\
	libsysfs/dlist.o
LIBSYSFS = libsysfs/libsysfs.a

# config files automatically generated
GEN_CONFIGS = \
	$(LOCAL_CFG_DIR)/udev.conf

GEN_HEADERS = \
	udev_version.h

# override this to make udev look in a different location for it's config files
prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
usrbindir =	${exec_prefix}/usr/bin
usrsbindir =	${exec_prefix}/usr/sbin
mandir =	${prefix}/usr/share/man
configdir =	${etcdir}/udev
udevdir =	/dev
udevdb =	${udevdir}/.udevdb
LOCAL_CFG_DIR =	etc/udev
KERNEL_DIR =	/lib/modules/${shell uname -r}/build
srcdir = .
DESTDIR =
RELEASE_NAME =	udev-$(VERSION)

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
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

# determine the gcc include dir
GCCINCDIR := ${shell LC_ALL=C $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}

# determine the libgcc.a filename
GCC_LIB := $(shell $(CC) -print-libgcc-file-name )

# check if compiler option is supported
cc-supports = ${shell if $(CC) ${1} -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;}

CFLAGS		+= -Wall -fno-builtin -Wchar-subscripts -Wpointer-arith \
		   -Wstrict-prototypes -Wsign-compare
CFLAGS		+= $(call cc-supports, -Wdeclaration-after-statement, )
CFLAGS		+= -pipe
CFLAGS		+= -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64

# use '-Os' optimization if available, else use -O2
OPTFLAGS := $(call cc-supports, -Os, -O2)

# include our local copy of libsysfs
CFLAGS +=	-I$(PWD)/libsysfs/sysfs	\
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
	CFLAGS  += $(OPTFLAGS) -fomit-frame-pointer
	LDFLAGS += -s -Wl
	STRIPCMD = $(STRIP) -s --remove-section=.note --remove-section=.comment
endif

# if our own version of klibc is used, we need to build it
ifeq ($(strip $(USE_KLIBC)),true)
	KLIBC_INSTALL	= $(PWD)/klibc/.install
	KLCC		= $(KLIBC_INSTALL)/bin/$(CROSS)klcc
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

all: $(KLCC) $(PROGRAMS) $(MAN_PAGES)
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) prefix=$(prefix) \
			LD="$(LD)" \
			LIBUDEV="$(PWD)/$(LIBUDEV)" \
			LIBSYSFS="$(PWD)/$(LIBSYSFS)" \
			KERNEL_DIR="$(KERNEL_DIR)" \
			QUIET="$(QUIET)" \
			-C $$target $@; \
	done;
.PHONY: all

$(PROGRAMS): $(HOST_PROGS) $(KLCC) $(HEADERS) $(GEN_HEADERS) $(LIBSYSFS) $(LIBUDEV)
	$(QUIET) $(CC) $(CFLAGS) -c -o $@.o $@.c
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $@.o $(LIBUDEV) $(LIBSYSFS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

# our own copy of klibc if KLCC is specified it will not be used
$(KLCC):
	$(MAKE) -j1 -C klibc KRNLSRC=$(KERNEL_DIR) SUBDIRS=klibc TESTS= \
			 SHLIBDIR=$(KLIBC_INSTALL)/lib \
			 INSTALLDIR=$(KLIBC_INSTALL) \
			 bindir=$(KLIBC_INSTALL)/bin \
			 mandir=$(KLIBC_INSTALL)/man all install
	-find $(KLIBC_INSTALL)/include -name SCCS -print| xargs rm -rf

$(UDEV_OBJS): $(KLCC)
$(LIBUDEV): $(HOST_PROGS) $(HEADERS) $(GEN_HEADERS) $(UDEV_OBJS)
	@rm -f $@
	$(QUIET) $(AR) cq $@ $(UDEV_OBJS)
	$(QUIET) $(RANLIB) $@

$(SYSFS_OBJS): $(KLCC)
$(LIBSYSFS): $(HOST_PROGS) $(SYSFS_OBJS)
	@rm -f $@
	$(QUIET) $(AR) cq $@ $(SYSFS_OBJS)
	$(QUIET) $(RANLIB) $@

# generate config files
$(GEN_CONFIGS):
	sed -e "s:@udevdir@:$(udevdir):" -e "s:@configdir@:$(configdir):" < $@.in > $@

# generate config header file
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

# man pages
%.8: docs/%.xml
	xmlto man $?
.PRECIOUS: %.8

.c.o:
	$(QUIET) $(CC) $(CFLAGS) -c -o $@ $<

ccdv: ccdv.c
	@$(HOSTCC) -O1 ccdv.c -o ccdv
.SILENT: ccdv

clean:
	-find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print | xargs rm -f
	-rm -f core $(PROGRAMS) $(GEN_HEADERS) $(GEN_CONFIGS)
	$(MAKE) -C klibc SUBDIRS=klibc clean
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) prefix=$(prefix) -C $$target $@; \
	done;
.PHONY: clean

spotless: clean
	$(MAKE) -C klibc SUBDIRS=klibc spotless
	rm -rf klibc/.install
.PHONY: spotless

release: spotless
	git-tar-tree HEAD $(RELEASE_NAME) | gzip -9v > $(RELEASE_NAME).tar.gz
	@echo "$(RELEASE_NAME).tar.gz created"
.PHONY: release

install-config: $(GEN_CONFIGS)
	$(INSTALL) -d $(DESTDIR)$(configdir)/rules.d
	@if [ ! -r $(DESTDIR)$(configdir)/udev.conf ]; then \
		echo $(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
		$(INSTALL_DATA) $(LOCAL_CFG_DIR)/udev.conf $(DESTDIR)$(configdir); \
	fi
	@if [ ! -r $(DESTDIR)$(configdir)/rules.d/50-udev.rules ]; then \
		echo; \
		echo "pick a udev rules file from the etc/udev directory that matches your distribution"; \
		echo; \
	fi
.PHONY: install-config

install-man:
	$(INSTALL_DATA) -D udev.8 $(DESTDIR)$(mandir)/man8/udev.8
	$(INSTALL_DATA) -D udevinfo.8 $(DESTDIR)$(mandir)/man8/udevinfo.8
	$(INSTALL_DATA) -D udevtest.8 $(DESTDIR)$(mandir)/man8/udevtest.8
	$(INSTALL_DATA) -D udevstart.8 $(DESTDIR)$(mandir)/man8/udevstart.8
	$(INSTALL_DATA) -D udevd.8 $(DESTDIR)$(mandir)/man8/udevd.8
	$(INSTALL_DATA) -D udevsend.8 $(DESTDIR)$(mandir)/man8/udevsend.8
	$(INSTALL_DATA) -D udevmonitor.8 $(DESTDIR)$(mandir)/man8/udevmonitor.8
	- ln -f -s udevd.8 $(DESTDIR)$(mandir)/man8/udevcontrol.8
.PHONY: install-man

uninstall-man:
	- rm $(mandir)/man8/udev.8
	- rm $(mandir)/man8/udevinfo.8
	- rm $(mandir)/man8/udevtest.8
	- rm $(mandir)/man8/udevstart.8
	- rm $(mandir)/man8/udevd.8
	- rm $(mandir)/man8/udevmonitor.8
	- rm $(mandir)/man8/udevsend.8
	- rm $(mandir)/man8/udevcontrol.8
.PHONY: uninstall-man

install: install-config install-man all
	$(INSTALL) -d $(DESTDIR)$(udevdir)
	$(INSTALL_PROGRAM) -D udev $(DESTDIR)$(sbindir)/udev
	$(INSTALL_PROGRAM) -D udevd $(DESTDIR)$(sbindir)/udevd
	$(INSTALL_PROGRAM) -D udevsend $(DESTDIR)$(sbindir)/udevsend
	$(INSTALL_PROGRAM) -D udevcontrol $(DESTDIR)$(sbindir)/udevcontrol
	$(INSTALL_PROGRAM) -D udevmonitor $(DESTDIR)$(usrsbindir)/udevmonitor
	$(INSTALL_PROGRAM) -D udevinfo $(DESTDIR)$(usrbindir)/udevinfo
	$(INSTALL_PROGRAM) -D udevtest $(DESTDIR)$(usrbindir)/udevtest
	$(INSTALL_PROGRAM) -D udevstart $(DESTDIR)$(sbindir)/udevstart
ifndef DESTDIR
	- killall udevd
	- rm -rf $(udevdb)
	- $(sbindir)/udevd --daemon
endif
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) prefix=$(prefix) -C $$target $@; \
	done;
.PHONY: install

uninstall: uninstall-man
	- rm $(configdir)/rules.d/50-udev.rules
	- rm $(configdir)/udev.conf
	- rmdir $(configdir)/rules.d
	- rmdir $(configdir)
	- rm $(sbindir)/udev
	- rm $(sbindir)/udevd
	- rm $(sbindir)/udevsend
	- rm $(sbindir)/udevinitsend
	- rm $(sbindir)/udeveventrecoreder
	- rm $(sbindir)/udevcontrol
	- rm $(sbindir)/udevstart
	- rm $(usrsbindir)/udevmonitor
	- rm $(usrbindir)/udevinfo
	- rm $(usrbindir)/udevtest
	- rm -rf $(udevdb)
	- rmdir $(udevdir)
	- killall udevd
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) prefix=$(prefix) -C $$target $@; \
	done;
.PHONY: uninstall-man

test tests: all
	@ cd test && ./udev-test.pl
	@ cd test && ./udevstart-test.pl
.PHONY: test tests

