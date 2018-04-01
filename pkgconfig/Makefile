DIR=	${LIBDIR}/pkgconfig
SRCS=	einfo.pc.in openrc.pc.in
INC=	einfo.pc openrc.pc

.DEFAULT:
	${SED} -n -e 's/^VERSION=[[:space:]]*\([^[:space:]]*\).*/#define VERSION "\1${GITVER}\"/p' ../../Makefile > version.h

SED_EXTRA=	-e 's:@VERSION@:${VERSION}:g'

MK=	../mk
include ../Makefile.inc
include ${MK}/scripts.mk
