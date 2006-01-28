# Makefile for udev extra invoked from the udev main Makefile
#
# Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
#
# Released under the GNU General Public License, version 2.
#

PROG = vol_id
LIBVOLUME_ID = libvolume_id/libvolume_id.a
GEN_HEADERS =
MAN_PAGES =

prefix =
etcdir =	${prefix}/etc
sbindir =	${prefix}/sbin
usrbindir =	${prefix}/usr/bin
usrsbindir =	${prefix}/usr/sbin
libudevdir =	${prefix}/lib/udev
mandir =	${prefix}/usr/share/man
configdir =	${etcdir}/udev/

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}

all: $(PROG) $(MAN_PAGES)
.PHONY: all
.DEFAULT: all

%.o: %.c $(GEN_HEADERS)
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

$(LIBVOLUME_ID):
	$(Q) $(MAKE) -C libvolume_id

$(PROG): %: $(HEADERS) %.o $(LIBVOLUME_ID)
	$(E) "  LD      " $@
	$(Q) $(LD) $(LDFLAGS) $@.o $(LIBVOLUME_ID) -o $@ $(LIBUDEV) $(LIB_OBJS)
ifneq ($(strip $(STRIPCMD)),)
	$(E) "  STRIP   " $@
	$(Q) $(STRIPCMD) $@
endif

# man pages
%.8: %.xml
	$(E) "  XMLTO   " $@
	$(Q) xmlto man $?
.PRECIOUS: %.8

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(PROG) $(OBJS) $(GEN_HEADERS)
	$(Q) $(MAKE) -C libvolume_id clean
.PHONY: clean

install-bin: all
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(sbindir)/$(PROG)
.PHONY: install-bin

uninstall-bin:
	- rm $(DESTDIR)$(sbindir)/$(PROG)
.PHONY: uninstall-bin

install-man:
	$(INSTALL_DATA) -D $(PROG).8 $(DESTDIR)$(mandir)/man8/$(PROG).8
.PHONY: uninstall-man

uninstall-man:
	-rm -f $(DESTDIR)$(mandir)/man8/$(PROG).8
.PHONY: uninstall-man

install-config:
	@echo "no config file to install"
.PHONY: install-config
