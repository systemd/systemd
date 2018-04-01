LIB=		rc
SHLIB_MAJOR=	1
SRCS=		librc.c librc-daemon.c librc-depend.c librc-misc.c \
		librc-stringlist.c
INCS=		rc.h
VERSION_MAP=	rc.map

LDADD+=		${LIBKVM}

LOCAL_CPPFLAGS+=	-I../includes

MK=		../../mk
include ${MK}/lib.mk
include ${MK}/cc.mk

# Massage our header file for our dirs
SED_CMD=	-e 's:@PREFIX@:${PREFIX}:g'
SED_CMD+=	-e 's:@LIB@:${LIBNAME}:g'
SED_CMD+=	-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'
SED_CMD+=	-e 's:@LIBEXECDIR@:${LIBEXECDIR}:g'
SED_CMD+=	-e 's:@BINDIR@:${BINDIR}:g'
SED_CMD+=	-e 's:@SBINDIR@:${SBINDIR}:g'

_PKG_PREFIX=	-e 's:.*@PKG_PREFIX@.*:\#undef RC_PKG_PREFIX:g'
ifneq (${PKG_PREFIX},)
ifneq (${PKG_PREFIX},/)
ifneq (${PKG_PREFIX},${PREFIX})
_PKG_PREFIX=	-e 's:@PKG_PREFIX@:${PKG_PREFIX}:g'
endif
endif
endif
SED_CMD+=	${_PKG_PREFIX}

_LCL_PREFIX=	-e 's:@LOCAL_PREFIX@::g'
ifneq (${LOCAL_PREFIX},)
ifneq (${LOCAL_PREFIX},/)
ifneq (${LOCAL_PREFIX},${PREFIX})
_LCL_PREFIX=	-e 's:@LOCAL_PREFIX@:${LOCAL_PREFIX}:g'
endif
endif
endif
SED_CMD+=	${_LCL_PREFIX}

%.h: %.h.in
	${SED} ${SED_CMD} $< > $@
${SRCS}:	rc.h

CLEANFILES+=	rc.h
