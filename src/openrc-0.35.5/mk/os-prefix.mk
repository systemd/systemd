# Copyright (c) 2012 William Hubbs <w.d.hubbs@gmail.com>
# Released under the 2-clause BSD license.

ifeq (${MKPREFIX},yes)
CPPFLAGS+=	-DPREFIX
PKG_PREFIX?=	$(PREFIX)/usr
SED_EXTRA=	-e '/_PATH=.*usr.bin/d'
endif
