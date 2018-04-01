# rules to make a distribution tarball from a git repo
# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

GITREF?=	${VERSION}
DISTPREFIX?=	${NAME}-${VERSION}
DISTFILE?=	${DISTPREFIX}.tar.gz

CLEANFILES+=	${NAME}-*.tar.gz

CHANGELOG_LIMIT?= --after="1 year ago"

_SNAP_SH=	date -u +%Y%m%d%H%M
_SNAP:=		$(shell ${_SNAP_SH})
SNAP=		${_SNAP}
SNAPDIR=	${DISTPREFIX}-${SNAP}
SNAPFILE=	${SNAPDIR}.tar.gz

changelog:
	git log ${CHANGELOG_LIMIT} --format=full > ChangeLog

dist:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} --output=${DISTFILE}

distcheck: dist
	rm -rf ${DISTPREFIX}
	tar xf ${DISTFILE}
	MAKEFLAGS= $(MAKE) -C ${DISTPREFIX}
	MAKEFLAGS= $(MAKE) -C ${DISTPREFIX} check
	rm -rf ${DISTPREFIX}

snapshot:
	rm -rf /tmp/${SNAPDIR}
	mkdir /tmp/${SNAPDIR}
	cp -RPp * /tmp/${SNAPDIR}
	(cd /tmp/${SNAPDIR}; make clean)
	rm -rf /tmp/${SNAPDIR}/.git 2>/dev/null || true
	tar -cvzpf ${SNAPFILE} -C /tmp ${SNAPDIR}
	rm -rf /tmp/${SNAPDIR}
	ls -l ${SNAPFILE}

snap: snapshot

