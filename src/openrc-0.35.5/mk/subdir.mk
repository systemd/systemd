# Recursive rules
# Adapted from FreeBSDs bsd.subdir.mk
# Copyright (c) 2007-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

_+_ ?= +
ECHODIR ?= echo
_SUBDIR = @${_+_}for x in ${SUBDIR}; do \
	if test -d $$x; then \
	${ECHODIR} "===> ${DIRPRFX}$$x (${@:realinstall=install})"; \
		cd $$x; \
		${MAKE} ${@:realinstall=install} \
		DIRPRFX=${DIRPRFX}$$x/ || exit $$?; \
		cd ..; \
	fi; \
done

all:
	${_SUBDIR}
clean:
	@if test -n "${CLEANFILES}"; then echo "rm -f ${CLEANFILES}"; rm -f ${CLEANFILES}; fi
	${_SUBDIR}
realinstall:
	${_SUBDIR}
install: realinstall ${INSTALLAFTER}
check test::
	${_SUBDIR}
depend:
	${_SUBDIR}
ignore:
	${_SUBDIR}
