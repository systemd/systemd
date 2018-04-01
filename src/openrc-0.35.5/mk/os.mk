# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

# Generic definitions

_OS_SH=		uname -s | tr '/' '-'
_OS:= 		$(shell ${_OS_SH})
OS?= 		${_OS}
include ${MK}/os-prefix.mk
include ${MK}/os-${OS}.mk

RC_LIB=		/$(LIBNAME)/rc
