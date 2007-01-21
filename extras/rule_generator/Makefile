# Makefile for udev extra invoked from the udev main Makefile
#
# Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
#
# Released under the GNU General Public License, version 2.
#

PROG =
MAN_PAGES =

prefix =
etcdir =	${prefix}/etc
sbindir =	${prefix}/sbin
usrbindir =	${prefix}/usr/bin
usrsbindir =	${prefix}/usr/sbin
libudevdir =	${prefix}/lib/udev
mandir =	${prefix}/usr/share/man
configdir =	${etcdir}/udev

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
	$(INSTALL_SCRIPT) -D rule_generator.functions $(DESTDIR)$(libudevdir)/rule_generator.functions
	$(INSTALL_SCRIPT) -D write_cd_rules $(DESTDIR)$(libudevdir)/write_cd_rules
	$(INSTALL_SCRIPT) -D write_net_rules $(DESTDIR)$(libudevdir)/write_net_rules
	$(INSTALL_DATA) -D 75-cd-aliases-generator.rules \
		$(DESTDIR)$(configdir)/rules.d/75-cd-aliases-generator.rules
	$(INSTALL_DATA) -D 75-persistent-net-generator.rules \
		$(DESTDIR)$(configdir)/rules.d/75-persistent-net-generator.rules
.PHONY: install-bin

uninstall-bin:
	- rm $(DESTDIR)$(libudevdir)/rule_generator.functions
	- rm $(DESTDIR)$(libudevdir)/write_cd_rules
	- rm $(DESTDIR)$(libudevdir)/write_net_rules
	- rm $(DESTDIR)$(configdir)/rules.d/75-cd-aliases-generator.rules
	- rm $(DESTDIR)$(configdir)/rules.d/75-persistent-net-generator.rules
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

