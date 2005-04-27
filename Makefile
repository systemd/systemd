# Makefile for diethotplug
#
# Copyright (C) 2000,2001 Greg Kroah-Hartman <greg@kroah.com>
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


ROOT =		udev
#PREFIX =	diet
VERSION =	0.01
INSTALL_DIR =	/usr/local/bin
RELEASE_NAME =	$(PREFIX)$(ROOT)-$(VERSION)


# Comment out this line to build with something other 
# than the local version of klibc
#KLIBC = true

# If you are running a cross compiler, you may want to set this
# to something more interesting, like "arm-linux-".  I you want
# to compile vs uClibc, that can be done here as well.
CROSS = #/usr/i386-linux-uclibc/usr/bin/i386-uclibc-
CC = $(CROSS)gcc
AR = $(CROSS)ar
STRIP = $(CROSS)strip


# code taken from uClibc to determine the current arch
ARCH := ${shell $(CC) -dumpmachine | sed -e s'/-.*//' -e 's/i.86/i386/' -e 's/sparc.*/sparc/' \
	-e 's/arm.*/arm/g' -e 's/m68k.*/m68k/' -e 's/ppc/powerpc/g'}

# code taken from uClibc to determine the gcc include dir
GCCINCDIR := ${shell $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}

# code taken from uClibc to determine the libgcc.a filename
GCC_LIB := $(shell $(CC) -print-libgcc-file-name )

# use '-Os' optimization if available, else use -O2
OPTIMIZATION := ${shell if $(CC) -Os -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
		then echo "-Os"; else echo "-O2" ; fi}

WARNINGS := -Wall -Wshadow -Wstrict-prototypes 

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
ifeq ($(strip $(KLIBC)),true)
	KLIBC_DIR	= klibc
	INCLUDE_DIR	:= $(KLIBC_DIR)/include
	# arch specific objects
	ARCH_LIB_OBJS =	\
			$(KLIBC_DIR)/bin-$(ARCH)/start.o	\
			$(KLIBC_DIR)/bin-$(ARCH)/klibc.a

	LIB_OBJS =	$(GCC_LIB)

	LIBC =	$(ARCH_LIB_OBJS) $(LIB_OBJS)
	CFLAGS += -nostdinc -I$(INCLUDE_DIR) -I$(GCCINCDIR)
	LDFLAGS = --static --nostdlib -nostartfiles
else
	LIBC = 
	CFLAGS += -I$(GCCINCDIR)
	LIB_OBJS = -lc
	LDFLAGS = --static 
endif

all: $(LIBC) $(ROOT)

$(ARCH_LIB_OBJS) :
	$(MAKE) -C klibc

OBJS =	udev.o		\
	logging.o


# header files automatically generated
GEN_HEADERS =	udev_version.h

# Rules on how to create the generated header files
udev_version.h:
	@echo \#define UDEV_VERSION \"$(VERSION)\" > $@


$(ROOT): $(GEN_HEADERS) $(OBJS)
	$(CC) $(LDFLAGS) -o $(ROOT) $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(STRIPCMD) $(ROOT)

clean:
	-find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print \
	 | xargs rm -f 
	-rm -f core $(ROOT) $(GEN_HEADERS)
	$(MAKE) -C klibc clean

DISTFILES = $(shell find . \( -not -name '.' \) -print | grep -v CVS | grep -v "\.tar\.gz" | grep -v "\/\." | grep -v releases | grep -v BitKeeper | grep -v SCCS )
DISTDIR := $(RELEASE_NAME)
srcdir = .
release: $(DISTFILES) clean
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
