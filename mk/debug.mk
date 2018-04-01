# rules to enable debugging support
# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

_RC_DEBUG_SH=	case "${DEBUG}" in "") echo "";; *) echo "-DRC_DEBUG";; esac
_RC_DEBUG:=	$(shell ${_RC_DEBUG_SH})
CPPFLAGS+=	${_RC_DEBUG}

# Should we enable this with a different flag?
_LD_DEBUG_SH=	case "${DEBUG}" in "") echo "";; *) echo "-Wl,--rpath=../librc -Wl,--rpath=../libeinfo";; esac
_LD_DEBUG:=	$(shell ${_LD_DEBUG_SH})
LDFLAGS+=	${_LD_DEBUG}

_GGDB_SH=	case "${DEBUG}" in "") echo "";; *) echo "-ggdb";; esac
_GGDB:=		$(shell ${_GGDB_SH})
CFLAGS+=	${_GGDB}
