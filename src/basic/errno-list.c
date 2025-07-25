/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errno-list.h"

static const struct errno_name* lookup_errno(register const char *str,
                                             register GPERF_LEN_TYPE len);

#include "errno-from-name.inc"
#include "errno-to-name.inc"

int errno_from_name(const char *name) {
        const struct errno_name *sc;

        assert(name);

        sc = lookup_errno(name, strlen(name));
        if (!sc)
                return -EINVAL;

        assert(sc->id > 0);
        return sc->id;
}

const char* errno_to_name(int id) {
        if (id == 0) /* To stay in line with our own impl */
                return NULL;

        if (id < 0)
                id = -id;

#if HAVE_STRERRORNAME_NP
        const char *n = strerrorname_np(id);
        if (n)
                return n;
#endif

        if ((size_t) id >= ELEMENTSOF(errno_names))
                return NULL;

        return errno_names[id];
}

const char* errno_name_full(int id, char buf[static ERRNO_NAME_BUF_LEN]) {
        const char *a = errno_to_name(id);
        if (a)
                return a;
        snprintf(buf, ERRNO_NAME_BUF_LEN, "%d", abs(id));
        return buf;
}
