# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

# Setup some good default CFLAGS
CFLAGS?=	-O2 -g

# Default to using the C99 standard
CSTD?=		c99
ifneq (${CSTD},)
CFLAGS+=	-std=${CSTD}
endif

# Try and use some good cc flags if we're building from git
# We don't use -pedantic as it will warn about our perfectly valid
# use of %m in our logger.
_CCFLAGS=	-Wall -Wextra -Wimplicit -Wshadow -Wformat=2 \
		-Wmissing-prototypes -Wmissing-declarations \
		-Wmissing-noreturn -Wmissing-format-attribute \
		-Wnested-externs \
		-Winline -Wwrite-strings -Wcast-align -Wcast-qual \
		-Wpointer-arith \
		-Wdeclaration-after-statement -Wsequence-point \
		-Werror=implicit-function-declaration

# We should be using -Wredundant-decls, but our library hidden proto stuff
# gives loads of warnings. I don't fully understand it (the hidden proto,
# not the warning) so we just silence the warning.

_CC_FLAGS_SH=	for f in ${_CCFLAGS}; do \
		if echo "int main(void) { return 0;} " | \
		${CC} $$f -S -xc -o /dev/null - ; \
		then printf "%s" "$$f "; fi \
		done;
_CC_FLAGS:=	$(shell ${_CC_FLAGS_SH})
CFLAGS+=	${_CC_FLAGS}

include ${MK}/debug.mk
