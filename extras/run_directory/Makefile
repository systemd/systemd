# Makefile for udev extra invoked from the udev main Makefile
#
# Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
#
# Released under the GNU General Public License, version 2.
#
PROG = udev_run_devd udev_run_hotplugd
OBJS = run_directory.o
HEADERS =
GEN_HEADERS =
MAN_PAGES =

prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
usrbindir =	${exec_prefix}/usr/bin
usrsbindir =	${exec_prefix}/usr/sbin
mandir =	${prefix}/usr/share/man
configdir =	${etcdir}/udev/
srcdir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}

all: $(PROG) $(MAN_PAGES)
.PHONY: all
.DEFAULT: all

%.o: %.c $(GEN_HEADERS)
	$(QUIET) $(CC) -c $(CFLAGS) $< -o $@

$(PROG): %: $(HEADERS) %.o $(OBJS)
	$(QUIET) $(LD) $(LDFLAGS) $@.o $(OBJS) -o $@ $(LIBUDEV) $(LIBSYSFS) $(LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

# man pages
%.8: %.xml
	xmlto man $?
.PRECIOUS: %.8

clean:
	rm -f $(PROG) $(OBJS) $(GEN_HEADERS)
.PHONY: clean

install-bin: all
	$(INSTALL_PROGRAM) udev_run_devd $(DESTDIR)$(sbindir)/udev_run_devd
	$(INSTALL_PROGRAM) udev_run_devd $(DESTDIR)$(sbindir)/udev_run_hotplugd
.PHONY: install-bin

uninstall-bin:
	- rm $(DESTDIR)$(sbindir)/udev_run_devd
	- rm $(DESTDIR)$(sbindir)/udev_run_hotplugd
.PHONY: uninstall-bin

install-man:
	@echo "Please create a man page for this tool."
.PHONY: uninstall-man

uninstall-man:
	@echo "Please create a man page for this tool."
.PHONY: uninstall-man

install-config:
	@echo "no config file to install"
.PHONY: install-config
