SUBDIRS = \
	udev \
	rules \
	extras

udevconfdir = $(sysconfdir)/udev
udevconf_DATA = \
	udev.conf

EXTRA_DIST = \
	udev.conf \
	docs \
	autogen.sh

distclean-local:
	rm -f *~
	rm -rf autom4te.cache
	rm -f depcomp aclocal.m4 config.h.in configure install-sh
	rm -f Makefile.in missing config.guess config.sub ltmain.sh
	rm -rf udev-test-install
	rm -f udev-$(VERSION).tar.gz udev-$(VERSION).tar.bz2

changelog:
	@ head -1 ChangeLog | grep -q "to v$(shell echo $$(($(VERSION) - 1)))"
	@ mv ChangeLog ChangeLog.tmp
	@ echo "Summary of changes from v$(shell echo $$(($(VERSION) - 1))) to v$(VERSION)" >> ChangeLog
	@ echo "============================================" >> ChangeLog
	@ echo >> ChangeLog
	@ git log --pretty=short $(shell echo $$(($(VERSION) - 1)))..HEAD | git shortlog  >> ChangeLog
	@ echo >> ChangeLog
	@ cat ChangeLog
	@ cat ChangeLog.tmp >> ChangeLog
	@ rm ChangeLog.tmp

test-run:
	cd test && ./udev-test.pl

test-install:
	rm -rf $(PWD)/udev-test-install/
	make DESTDIR=$(PWD)/udev-test-install install
	tree $(PWD)/udev-test-install/

