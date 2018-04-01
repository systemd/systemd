# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

SFX=		.Linux.in
PKG_PREFIX?=	/usr

CPPFLAGS+=	-D_DEFAULT_SOURCE
LIBDL=		-Wl,-Bdynamic -ldl

ifeq (${MKSELINUX},yes)
CPPFLAGS+= -DHAVE_SELINUX
LIBSELINUX?= -lselinux
LDADD += $(LIBSELINUX)

ifneq (${MKPAM},pam)
# if using selinux but not pam then we need crypt
LIBCRYPT?= -lcrypt
LDADD += $(LIBCRYPT)
endif

endif

ifeq (${MKAUDIT},yes)
LIBAUDIT?=	-laudit
CPPFLAGS+=	-DHAVE_AUDIT
LDADD+=		${LIBAUDIT}
endif
