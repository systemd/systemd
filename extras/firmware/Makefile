# Makefile for udev extra invoked from the udev main Makefile
#
# Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
#
# Released under the GNU General Public License, version 2.
#

PROG = firmware.sh
MAN_PAGES =

prefix =
etcdir =	${prefix}/etc
sbindir =	${prefix}/sbin
usrbindir =	${prefix}/usr/bin
usrsbindir =	${prefix}/usr/sbin
libudevdir =	${prefix}/lib/udev
mandir =	${prefix}/usr/share/man
configdir =	${etcdir}/udev/

INSTALL = install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL}

all: $(PROG) $(MAN_PAGES)
.PHONY: all
.DEFAULT: all

# man pages
%.8: %.xml
	$(E) "  XMLTO   " $@
	$(Q) xmlto man $?
.PRECIOUS: %.8

clean:
	$(E) "  CLEAN   "
.PHONY: clean

install-bin: all
	$(INSTALL_SCRIPT) -D $(PROG) $(DESTDIR)$(libudevdir)/$(PROG)
.PHONY: install-bin

uninstall-bin:
	- rm $(DESTDIR)$(libudevdir)/$(PROG)
.PHONY: uninstall-bin

install-man:
	@echo "Please create a man page for this tool."
.PHONY: install-man

uninstall-man:
	@echo "Please create a man page for this tool."
.PHONY: uninstall-man

install-config:
	@echo "no config file to install"
.PHONY: install-config

