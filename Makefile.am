#  This file is part of systemd.
#
#  Copyright 2011 Lennart Poettering
#  Copyright 2011 Kay Sievers
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4
SUBDIRS =

CLEANFILES =
EXTRA_DIST =
INSTALL_EXEC_HOOKS =
UNINSTALL_EXEC_HOOKS =
INSTALL_DATA_HOOKS =

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I $(top_srcdir)/src

bin_PROGRAMS = \
	systemadm \
	systemd-gnome-ask-password-agent

systemadm_SOURCES = \
	src/systemadm.vala \
	src/systemd-interfaces.vala

systemadm_CFLAGS = \
	$(AM_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GEE_CFLAGS) \
	-Wno-unused-variable \
	-Wno-unused-function \
	-Wno-shadow \
	-Wno-format-nonliteral

systemadm_VALAFLAGS = \
	--pkg=posix \
	--pkg=gtk+-3.0 \
	--pkg=$(GEE_PACKAGE) \
	-g

systemadm_LDADD = \
	$(GTK_LIBS) \
	$(GEE_LIBS)

desktopdir = $(datadir)/applications
dist_desktop_DATA = \
	src/systemadm.desktop

appdatadir = $(datadir)/appdata
dist_appdata_DATA = \
	src/systemadm.appdata.xml

CLEANFILES += \
	${systemadm_SOURCES:.vala=.c}

dist_man_MANS = \
	man/systemadm.1

EXTRA_DIST += \
	man/systemadm.xml

systemd_gnome_ask_password_agent_SOURCES = \
	src/gnome-ask-password-agent.vala

systemd_gnome_ask_password_agent_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBNOTIFY_CFLAGS) \
	$(GTK_CFLAGS) \
	-Wno-unused-variable \
	-Wno-unused-function \
	-Wno-shadow \
	-Wno-format-nonliteral

systemd_gnome_ask_password_agent_VALAFLAGS = \
	--pkg=posix \
	--pkg=gtk+-3.0 \
	--pkg=linux \
	--pkg=gio-unix-2.0 \
	--pkg=libnotify \
	-g

systemd_gnome_ask_password_agent_LDADD = \
	$(LIBNOTIFY_LIBS) \
	$(GTK_LIBS)

CLEANFILES += \
	${systemd_gnome_ask_password_agent_SOURCES:.vala=.c}

if HAVE_XSLTPROC
XSLTPROC_FLAGS = \
	--nonet \
	--stringparam funcsynopsis.style ansi

XSLTPROC_PROCESS_MAN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

man/%.1: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

CLEANFILES += \
	$(dist_man_MANS)
endif

install-exec-hook: $(INSTALL_EXEC_HOOKS)
uninstall-hook: $(UNINSTALL_EXEC_HOOKS)
install-data-hook: $(INSTALL_DATA_HOOKS)

upload: all distcheck
	scp systemd-ui-$(VERSION).tar.xz www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd/

git-tag:
	git tag "v$(VERSION)" -m "systemd-ui $(VERSION)"
