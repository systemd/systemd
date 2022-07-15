#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# In kernel's arch/parisc/include/uapi/asm/errno.h, ECANCELLED and EREFUSED are defined as aliases of
# ECANCELED and ECONNREFUSED, respectively. Let's drop them.

${1:?} -dM -include errno.h - </dev/null | \
       grep -Ev '^#define[[:space:]]+(ECANCELLED|EREFUSED)' | \
       awk '/^#define[ \t]+E[^ _]+[ \t]+/ { print $2; }'
