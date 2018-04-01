# rules to make .gitignore files
# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
# except according to the terms contained in the LICENSE file.

IGNOREFILES+=   ${CLEANFILES}

.PHONY:         .gitignore

.gitignore:
	@if test -n "${IGNOREFILES}"; then \
		echo "Ignoring ${IGNOREFILES}"; \
		echo ${IGNOREFILES} | tr ' ' '\n' > .gitignore; \
	fi

ignore: .gitignore
