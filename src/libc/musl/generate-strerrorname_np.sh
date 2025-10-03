#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# This is based on src/basic/generate-errno-list.sh.

# ECANCELLED, EDEADLOCK, ENOTSUP, EREFUSED, and EWOULDBLOCK are defined as aliases of
# ECANCELED, EDEADLK, EOPNOTSUPP, ECONNREFUSED, and EAGAIN, respectively. Let's drop them.

CC=${1:?}
shift

cat <<'EOF'
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>

static const char * const errno_table[] = {
EOF

$CC -dM -include errno.h - </dev/null | \
    grep -Ev '^#define[[:space:]]+(ECANCELLED|EDEADLOCK|ENOTSUP|EREFUSED|EWOULDBLOCK)' | \
    awk '/^#define[ \t]+E[^ _]+[ \t]+/ { printf "        [%s] = \"%s\",\n", $2, $2; }' | \
    sort

cat <<'EOF'
};

const char* strerrorname_np(int errnum) {
        if (errnum < 0)
                errnum = -errnum;
        if ((size_t) errnum >= sizeof(errno_table) / sizeof(errno_table[0]))
                return NULL;
        return errno_table[errnum];
}
EOF
