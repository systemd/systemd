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

VERSION = 075

# set this to make use of syslog
USE_LOG = true

# compile-in development debug messages
# (export UDEV_LOG="debug" or set udev_log="debug" in udev.conf
#  to print the debug messages to syslog)
DEBUG = false

# compile with gcc's code coverage option
USE_GCOV = false

# include Security-Enhanced Linux support
USE_SELINUX = false

# comile with klibc instead of glibc
USE_KLIBC = false

# set this to create statically linked binaries
USE_STATIC = false

# to build any of the extras programs pass:
#  make EXTRAS="extras/<extra1> extras/<extra2>"
EXTRAS =

# make the build silent. Set this to something else to make it noisy again.
V = false

PROGRAMS = \
	udev				\
	udevd				\
	udevsend			\
	udevcontrol			\
	udevmonitor			\
	udevinfo			\
	udevtest			\
	udevstart

HEADERS = \
	udev.h				\
	udev_utils.h			\
	udev_rules.h			\
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
DESTDIR =

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
PWD = $(shell pwd)

CROSS =
CC = $(CROSS)gcc
LD = $(CROSS)gcc
AR = $(CROSS)ar
RANLIB = $(CROSS)ranlib
HOSTCC = gcc
STRIP = $(CROSS)strip
STRIPCMD = $(STRIP) -s

# check if compiler option is supported
cc-supports = ${shell if $(CC) ${1} -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;}

CFLAGS		= -g -Wall -pipe -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
WARNINGS	= -Wstrict-prototypes -Wsign-compare -Wshadow \
		  -Wchar-subscripts -Wmissing-declarations -Wnested-externs \
		  -Wpointer-arith -Wcast-align -Wsign-compare -Wmissing-prototypes
WARNINGS	+= $(call cc-supports, -Wdeclaration-after-statement, )
CFLAGS		+= $(WARNINGS)

LDFLAGS = -Wl,-warn-common

# use -Os optimization if available, else use -O2
OPTFLAGS := $(call cc-supports, -Os, -O2)
CFLAGS += $(OPTFLAGS)

# include our local copy of libsysfs
CFLAGS +=	-I$(PWD)/libsysfs/sysfs	\
		-I$(PWD)/libsysfs

ifeq ($(strip $(USE_LOG)),true)
	CFLAGS += -DUSE_LOG
endif

# if DEBUG is enabled, then we do not strip
ifeq ($(strip $(DEBUG)),true)
	CFLAGS  += -DDEBUG
	STRIPCMD =
endif

ifeq ($(strip $(USE_GCOV)),true)
	CFLAGS += -fprofile-arcs -ftest-coverage
	LDFLAGS += -fprofile-arcs
endif

# if our own version of klibc is used, we need to build it
ifeq ($(strip $(USE_KLIBC)),true)
	KLCC		= /usr/bin/$(CROSS)klcc
	CC		= $(KLCC)
	LD		= $(KLCC)
	V = true
endif

ifeq ($(strip $(USE_SELINUX)),true)
	UDEV_OBJS += udev_selinux.o
	LIB_OBJS += -lselinux -lsepol
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

all: $(PROGRAMS) $(MAN_PAGES)
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) CC="$(CC)" \
			CFLAGS="$(CFLAGS)" \
			LD="$(LD)" \
			LDFLAGS="$(LDFLAGS)" \
			STRIPCMD="$(STRIPCMD)" \
			LIB_OBJS="$(LIB_OBJS)" \
			LIBUDEV="$(PWD)/$(LIBUDEV)" \
			LIBSYSFS="$(PWD)/$(LIBSYSFS)" \
			QUIET="$(QUIET)" \
			-C $$target $@; \
	done;
.PHONY: all
.DEFAULT: all

# clear implicit rules
.SUFFIXES:

# build the objects
%.o: %.c $(GEN_HEADERS)
	$(QUIET) $(CC) -c $(CFLAGS) $< -o $@

# "Static Pattern Rule" to build all programs
$(PROGRAMS): %: $(HOST_PROGS) $(HEADERS) $(GEN_HEADERS) $(LIBSYSFS) $(LIBUDEV) %.o
	$(QUIET) $(LD) $(LDFLAGS) $@.o -o $@ $(LIBUDEV) $(LIBSYSFS) $(LIB_OBJS)
ifneq ($(STRIPCMD),)
	$(QUIET) $(STRIPCMD) $@
endif

$(UDEV_OBJS):
$(LIBUDEV): $(HOST_PROGS) $(HEADERS) $(GEN_HEADERS) $(UDEV_OBJS)
	@rm -f $@
	$(QUIET) $(AR) cq $@ $(UDEV_OBJS)
	$(QUIET) $(RANLIB) $@

$(SYSFS_OBJS):
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
	@echo \#define UDEVD_BIN		\"$(sbindir)/udevd\" >> $@

# man pages
%.8: docs/%.xml
	xmlto man $?
.PRECIOUS: %.8

ccdv: ccdv.c
	@$(HOSTCC) -O1 ccdv.c -o ccdv
.SILENT: ccdv

clean:
	- find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print0 | xargs -0rt rm -f
	- find -name "*.gcno" -print0 | xargs -0rt rm -f
	- find -name "*.gcda" -print0 | xargs -0rt rm -f
	- find -name "*.gcov" -print0 | xargs -0rt rm -f
	- rm -f udev_gcov.txt
	- rm -f core $(PROGRAMS) $(GEN_HEADERS) $(GEN_CONFIGS)
	- rm -f udev-$(VERSION).tar.gz
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) -C $$target $@; \
	done;
.PHONY: clean

release:
	git-tar-tree HEAD udev-$(VERSION) | gzip -9v > udev-$(VERSION).tar.gz
	@echo "udev-$(VERSION).tar.gz created"
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
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) -C $$target $@; \
	done;
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
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) -C $$target $@; \
	done;
.PHONY: install-man

uninstall-man:
	- rm -f $(DESTDIR)$(mandir)/man8/udev.8
	- rm -f $(DESTDIR)$(mandir)/man8/udevinfo.8
	- rm -f $(DESTDIR)$(mandir)/man8/udevtest.8
	- rm -f $(DESTDIR)$(mandir)/man8/udevstart.8
	- rm -f $(DESTDIR)$(mandir)/man8/udevd.8
	- rm -f $(DESTDIR)$(mandir)/man8/udevmonitor.8
	- rm -f $(DESTDIR)$(mandir)/man8/udevsend.8
	- rm -f $(DESTDIR)$(mandir)/man8/udevcontrol.8
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) -C $$target $@; \
	done;
.PHONY: uninstall-man

install-bin:
	$(INSTALL) -d $(DESTDIR)$(udevdir)
	$(INSTALL_PROGRAM) -D udev $(DESTDIR)$(sbindir)/udev
	$(INSTALL_PROGRAM) -D udevd $(DESTDIR)$(sbindir)/udevd
	$(INSTALL_PROGRAM) -D udevsend $(DESTDIR)$(sbindir)/udevsend
	$(INSTALL_PROGRAM) -D udevcontrol $(DESTDIR)$(sbindir)/udevcontrol
	$(INSTALL_PROGRAM) -D udevmonitor $(DESTDIR)$(usrsbindir)/udevmonitor
	$(INSTALL_PROGRAM) -D udevinfo $(DESTDIR)$(usrbindir)/udevinfo
	$(INSTALL_PROGRAM) -D udevtest $(DESTDIR)$(usrbindir)/udevtest
	$(INSTALL_PROGRAM) -D udevstart $(DESTDIR)$(sbindir)/udevstart
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) -C $$target $@; \
	done;
ifndef DESTDIR
	- killall udevd
	- rm -rf $(udevdb)
	- $(sbindir)/udevd --daemon
endif
.PHONY: install-bin

uninstall-bin:
	- rm -f $(DESTDIR)$(sbindir)/udev
	- rm -f $(DESTDIR)$(sbindir)/udevd
	- rm -f $(DESTDIR)$(sbindir)/udevsend
	- rm -f $(DESTDIR)$(sbindir)/udevcontrol
	- rm -f $(DESTDIR)$(sbindir)/udevstart
	- rm -f $(DESTDIR)$(usrsbindir)/udevmonitor
	- rm -f $(usrbindir)/udevinfo
	- rm -f $(DESTDIR)$(DESTDIR)$(usrbindir)/udevtest
ifndef DESTDIR
	- killall udevd
	- rm -rf $(udevdb)
endif
	@extras="$(EXTRAS)"; for target in $$extras; do \
		echo $$target; \
		$(MAKE) -C $$target $@; \
	done;
.PHONY: uninstall-bin

install: all install-bin install-config install-man
.PHONY: install

uninstall: uninstall-bin uninstall-man
.PHONY: uninstall

test tests: all
	@ cd test && ./udev-test.pl
	@ cd test && ./udevstart-test.pl
.PHONY: test tests

buildtest:
	./test/simple-build-check.sh
.PHONY: buildtest

gcov-all:
	$(MAKE) clean all STRIPCMD= USE_GCOV=true
	@echo
	@echo "binaries built with gcov support."
	@echo "run the tests and analyze with 'make udev_gcov.txt'"
.PHONY: gcov-all

# see docs/README-gcov_for_udev
udev_gcov.txt: $(wildcard *.gcda) $(wildcard *.gcno)
	for file in `find -maxdepth 1 -name "*.gcno"`; do \
		name=`basename $$file .gcno`; \
		echo "################" >> $@; \
		echo "$$name.c" >> $@; \
		echo "################" >> $@; \
		if [ -e "$$name.gcda" ]; then \
			gcov -l "$$name.c" >> $@ 2>&1; \
		else \
			echo "code for $$name.c was never executed" >> $@ 2>&1; \
		fi; \
		echo >> $@; \
	done; \
	echo "view $@ for the result"

