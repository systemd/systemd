# Install rules for our scripts
# Copyright (c) 2007-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

include ${MK}/sys.mk
include ${MK}/os.mk

OBJS+=	${SRCS:.in=}

_PKG_SED_SH=		if test "${PREFIX}" = "${PKG_PREFIX}"; then echo "-e 's:@PKG_PREFIX@::g'"; else echo "-e 's:@PKG_PREFIX@:${PKG_PREFIX}:g'"; fi
_PKG_SED:=		$(shell ${_PKG_SED_SH})
_LCL_SED_SH=		if test "${PREFIX}" = "${LOCAL_PREFIX}"; then echo "-e 's:@LOCAL_PREFIX@::g'"; else echo "-e 's:@LOCAL_PREFIX@:${LOCAL_PREFIX}:g'"; fi
_LCL_SED:=		$(shell ${_LCL_SED_SH})

SED_REPLACE=		-e 's:@SHELL@:${SH}:g' -e 's:@LIB@:${LIBNAME}:g' -e 's:@SYSCONFDIR@:${SYSCONFDIR}:g' -e 's:@LIBEXECDIR@:${LIBEXECDIR}:g' -e 's:@PREFIX@:${PREFIX}:g' -e 's:@BINDIR@:${BINDIR}:g' -e 's:@SBINDIR@:${SBINDIR}:g' ${_PKG_SED} ${_LCL_SED}

# Tweak our shell scripts
%.sh: %.sh.in
	${SED} ${SED_REPLACE} ${SED_EXTRA} $< > $@

%: %.in
	${SED} ${SED_REPLACE} ${SED_EXTRA} $< > $@

all: ${OBJS} ${TARGETS}

realinstall: ${BIN} ${CONF} ${INC}
	@if test -n "${DIR}"; then \
		${ECHO} ${INSTALL} -d ${DESTDIR}/${DIR}; \
		${INSTALL} -d ${DESTDIR}/${DIR} || exit $$?; \
	fi
	@if test -n "${BIN}"; then \
		${ECHO} ${INSTALL} -m ${BINMODE} ${BIN} ${DESTDIR}/${DIR}; \
		${INSTALL} -m ${BINMODE} ${BIN} ${DESTDIR}/${DIR} || exit $$?; \
	fi
	@if test -n "${INC}"; then \
		${ECHO} ${INSTALL} -m ${INCMODE} ${INC} ${DESTDIR}/${DIR}; \
		${INSTALL} -m ${INCMODE} ${INC} ${DESTDIR}/${DIR} || exit $$?; \
	fi
	@for x in ${CONF}; do \
		if ! test -e ${DESTDIR}/${PREFIX}${DIR}/$$x; then \
			${ECHO} ${INSTALL} -m ${CONFMODE} $$x ${DESTDIR}/${DIR}; \
			${INSTALL} -m ${CONFMODE} $$x ${DESTDIR}/${DIR} || exit $$?; \
		fi; \
	done

install: all realinstall ${INSTALLAFTER}

check test::
	@if test -e runtests.sh ; then ./runtests.sh || exit $$? ; fi

# A lot of scripts don't have anything to clean
# Also, some rm implentation require a file argument regardless of error
# so we ensure that it has a bogus argument
CLEANFILES+=	${OBJS}
clean:
	@if test -n "${CLEANFILES}"; then echo "rm -f ${CLEANFILES}"; rm -f ${CLEANFILES}; fi

include ${MK}/gitignore.mk
