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

dist_html_DATA = README.html style.css
EXTRA_DIST = README.html.in

MAINTAINERCLEANFILES = README.html
CLEANFILES =

if USE_LYNX
dist_doc_DATA = README
MAINTAINERCLEANFILES += README

README: README.html
	lynx --dump $^ | sed 's,file://localhost/.*/doc/README.html,README,' > $@

CLEANFILES += README
endif

tidy: README.html
	tidy -qe < README.html ; true

.PHONY: tidy
