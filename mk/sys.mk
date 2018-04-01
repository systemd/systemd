# Generic system definitions
# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

AR?=			ar
CP?=			cp
PKG_CONFIG?=	pkg-config
ECHO?=			echo
INSTALL?=		install
RANLIB?=		ranlib
SED?=			sed
SH=			/bin/sh

PREFIX?=
ifeq (${PREFIX},)
UPREFIX= /usr
else
UPREFIX= ${PREFIX}
ifeq (${MKPREFIX},yes)
UPREFIX= ${PREFIX}/usr
endif
endif
LOCAL_PREFIX=		$(UPREFIX)/local

PICFLAG?=		-fPIC

SYSCONFDIR?=		${PREFIX}/etc
INITDIR?=		${SYSCONFDIR}/init.d
CONFDIR?=		${SYSCONFDIR}/conf.d
CONFMODE?=		0644
LOCALDIR?=		${SYSCONFDIR}/local.d
SYSCTLDIR?=		${SYSCONFDIR}/sysctl.d

BINDIR?=		${PREFIX}/bin
BINMODE?=		0755

SBINDIR?=		${PREFIX}/sbin
SBINMODE?=		0755

INCDIR?=		${UPREFIX}/include
INCMODE?=		0444

_LIBNAME_SH=		case `readlink /lib` in /lib64|lib64) echo "lib64";; *) echo "lib";; esac
_LIBNAME:=		$(shell ${_LIBNAME_SH})
LIBNAME?=		${_LIBNAME}
LIBDIR?=		${UPREFIX}/${LIBNAME}
LIBMODE?=		0444
SHLIBDIR?=		${PREFIX}/${LIBNAME}

LIBEXECDIR?=		${PREFIX}/libexec/rc

MANPREFIX?=		${UPREFIX}/share
MANDIR?=		${MANPREFIX}/man
MANMODE?=		0444

BASHCOMPDIR?=		${UPREFIX}/share/bash-completion/completions

DATADIR?=		${UPREFIX}/share/openrc
DATAMODE?=		0644

DOCDIR?=		${UPREFIX}/share/doc
DOCMODE?=		0644

ZSHCOMPDIR?=		${UPREFIX}/share/zsh/site-functions
