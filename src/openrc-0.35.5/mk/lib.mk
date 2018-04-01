# rules to build a library
# based on FreeBSD's bsd.lib.mk

# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

SHLIB_NAME=		lib${LIB}.so.${SHLIB_MAJOR}
SHLIB_LINK=		lib${LIB}.so
SONAME?=		${SHLIB_NAME}

SOBJS+=			${SRCS:.c=.So}

MKSTATICLIBS?=  yes
ifeq (${MKSTATICLIBS},yes)
OBJS+=			${SRCS:.c=.o}
_LIBS+=			lib${LIB}.a
endif

_LIBS+=			${SHLIB_NAME}

CLEANFILES+=		${OBJS} ${SOBJS} ${_LIBS} ${SHLIB_LINK}

%.o: %.c
	${CC} ${LOCAL_CFLAGS} ${LOCAL_CPPFLAGS} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

%.So: %.c
	${CC} ${PICFLAG} -DPIC ${LOCAL_CFLAGS} ${LOCAL_CPPFLAGS} ${CPPFLAGS} ${CFLAGS} -c $< -o $@

all: depend ${_LIBS}

lib${LIB}.a:	${OBJS} ${STATICOBJS}
	@${ECHO} building static library $@
	${AR} rc $@ $^
	${RANLIB} $@

${SHLIB_NAME}: ${VERSION_MAP}
LDFLAGS+=	-Wl,--version-script=${VERSION_MAP}

${SHLIB_NAME}:	${SOBJS}
	@${ECHO} building shared library $@
	@rm -f $@ ${SHLIB_LINK}
	@ln -fs $@ ${SHLIB_LINK}
	${CC} ${LOCAL_CFLAGS} ${CFLAGS} ${LOCAL_LDFLAGS} ${LDFLAGS} -shared -Wl,-x \
	-o $@ -Wl,-soname,${SONAME} \
	${SOBJS} ${LDADD}

install: all
ifeq (${MKSTATICLIBS},yes)
	${INSTALL} -d ${DESTDIR}${LIBDIR}
	${INSTALL} -m ${LIBMODE} lib${LIB}.a ${DESTDIR}${LIBDIR}
endif
	${INSTALL} -d ${DESTDIR}${SHLIBDIR}
	${INSTALL} -m ${LIBMODE} ${SHLIB_NAME} ${DESTDIR}${SHLIBDIR}
	ln -fs ${SHLIB_NAME} ${DESTDIR}${SHLIBDIR}/${SHLIB_LINK}
	${INSTALL} -d ${DESTDIR}${INCDIR}
	for x in ${INCS}; do ${INSTALL} -m ${INCMODE} $$x ${DESTDIR}${INCDIR}; done

check test::

clean:
	rm -f ${OBJS} ${SOBJS} ${_LIBS} ${SHLIB_LINK} ${CLEANFILES}

extra_depend:
	@TMP=depend.$$$$; \
	${SED} -e 's/^\([^\.]*\).o[ ]*:/\1.o \1.So:/' .depend > $${TMP}; \
	mv $${TMP} .depend

include ${MK}/sys.mk
include ${MK}/os.mk
include ${MK}/depend.mk
include ${MK}/gitignore.mk
