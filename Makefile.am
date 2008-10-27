# This file is part of nss-myhostname.
#
# Copyright 2008 Lennart Poettering
#
# nss-myhostname is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# nss-myhostname is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with nss-myhostname. If not, If not, see
# <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libnss_myhostname.la

EXTRA_DIST=bootstrap.sh README LICENSE
SUBDIRS=doc

MAINTAINERCLEANFILES=README
noinst_DATA = README

README:
	rm -f README
	$(MAKE) -C doc README
	cd $(srcdir) && ln -s doc/README README

homepage: all dist
	test -d $$HOME/homepage/private
	mkdir -p $$HOME/homepage/private/projects/nss-myhostname
	cp nss-myhostname-@PACKAGE_VERSION@.tar.gz doc/README.html doc/style.css $$HOME/homepage/private/projects/nss-myhostname
	ln -sf README.html $$HOME/homepage/private/projects/nss-myhostname/index.html

.PHONY: homepage

libnss_myhostname_la_SOURCES = nss-myhostname.c
libnss_myhostname_la_LDFLAGS = -avoid-version -module -export-dynamic -shrext .so.2

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/libnss_myhostname.la
	rm -f $(DESTDIR)$(libdir)/libnss_myhostname_minimal.la

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/libnss_myhostname.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_myhostname_minimal.so.2
