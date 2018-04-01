# Copyright (c) 2007-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

SFX=		.GNU.in
PKG_PREFIX?=	/usr

CPPFLAGS+=	-D_DEFAULT_SOURCE -DMAXPATHLEN=4096 -DPATH_MAX=4096
LIBDL=		-Wl,-Bdynamic -ldl
