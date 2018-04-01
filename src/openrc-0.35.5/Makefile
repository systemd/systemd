# Copyright (c) 2007-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

TOP:=		${dir ${realpath ${firstword ${MAKEFILE_LIST}}}}
MK=			${TOP}/mk

include ${TOP}/Makefile.inc

SUBDIR=		conf.d etc init.d local.d man scripts sh src support sysctl.d

# Build bash completion or not
MKBASHCOMP?=	no
ifeq (${MKBASHCOMP},yes)
SUBDIR+=	bash-completion
endif

# Build pkgconfig or not
MKPKGCONFIG?=	yes
ifeq (${MKPKGCONFIG},yes)
SUBDIR+=	pkgconfig
endif

# Build zsh completion or not
MKZSHCOMP?=	no
ifeq (${MKZSHCOMP},yes)
SUBDIR+=	zsh-completion
endif

# We need to ensure that runlevels is done last
SUBDIR+=	runlevels

INSTALLAFTER=	_installafter

include ${MK}/sys.mk
include ${MK}/os.mk
include ${MK}/subdir.mk
include ${MK}/dist.mk
include ${MK}/gitver.mk

_installafter:
ifeq (${MKPREFIX},yes)
	${INSTALL} -d ${DESTDIR}/${LIBEXECDIR}/init.d
else ifneq (${OS},Linux)
	${INSTALL} -d ${DESTDIR}/${LIBEXECDIR}/init.d
endif
	${INSTALL} -d ${DESTDIR}/${LIBEXECDIR}/tmp
	${ECHO} "${VERSION}${GITVER}" > ${DESTDIR}/${LIBEXECDIR}/version
