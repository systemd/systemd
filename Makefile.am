include $(top_srcdir)/Makefile.am.inc

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

CLEANFILES = \
	udev-$(VERSION).tar.gz udev-$(VERSION).tar.bz2

clean-local:
	rm -rf udev-test-install

distclean-local:
	rm -rf autom4te.cache

PREVIOUS_VERSION = `expr $(VERSION) - 1`

changelog:
	@ head -1 ChangeLog | grep -q "to v$(PREVIOUS_VERSION)"
	@ mv ChangeLog ChangeLog.tmp
	@ echo "Summary of changes from v$(PREVIOUS_VERSION) to v$(VERSION)" >> ChangeLog
	@ echo "============================================" >> ChangeLog
	@ echo >> ChangeLog
	@ git log --pretty=short $(PREVIOUS_VERSION)..HEAD | git shortlog  >> ChangeLog
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

git-release:
	head -1 ChangeLog | grep -q "to v$(VERSION)"
	head -1 NEWS | grep -q "udev $(VERSION)"
	git commit -a -m "release $(VERSION)"
	cat .git/refs/heads/master > .git/refs/tags/$(VERSION)
	git gc
	git prune
