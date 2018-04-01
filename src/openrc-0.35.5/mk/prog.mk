# rules to build a program
# based on FreeBSD's bsd.prog.mk

# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

OBJS+=			${SRCS:.c=.o}

# Some systems don't include /lib in their standard link path
# so we should embed it if different
# This is currently hardcoded for NetBSD which has two dynamic linkers
# and we need to use the one in /libexec instead of /usr/libexec
_DYNLINK_SH=		if test "${PREFIX}" = "" && test -e /libexec/ld.elf_so; then \
				echo "-Wl,-dynamic-linker=/libexec/ld.elf_so"; \
			else \
				echo ""; \
			fi
_DYNLINK:=		$(shell ${_DYNLINK_SH})
LDFLAGS+=		${_DYNLINK}
LDFLAGS+=		-Wl,-rpath=${PREFIX}/${LIBNAME}
LDFLAGS+=		${PROGLDFLAGS}

CLEANFILES+=		${OBJS} ${PROG}

all: depend ${PROG}

%.o: %.c
	${CC} ${LOCAL_CFLAGS} ${LOCAL_CPPFLAGS} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

${PROG}: ${SCRIPTS} ${OBJS}
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS}  ${CFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

clean:
	rm -f ${CLEANFILES}

extra_depend:

include ${MK}/sys.mk
include ${MK}/os.mk
include ${MK}/depend.mk
include ${MK}/gitignore.mk
