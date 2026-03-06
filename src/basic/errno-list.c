/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errno-list.h"

static const struct errno_name* lookup_errno(register const char *str,
                                             register GPERF_LEN_TYPE len);

#include "errno-from-name.inc"

int errno_from_name(const char *name) {
        const struct errno_name *sc;

        assert(name);

        sc = lookup_errno(name, strlen(name));
        if (!sc)
                return -EINVAL;

        assert(sc->id > 0);
        return sc->id;
}

#ifdef __GLIBC__
const char* errno_name_no_fallback(int id) {
        if (id == 0) /* To stay in line with our implementation below.  */
                return NULL;

        return strerrorname_np(ABS(id));
}
#else
#  include "errno-to-name.inc"

const char* errno_name_no_fallback(int id) {
        if (id < 0)
                id = -id;

        if ((size_t) id >= ELEMENTSOF(errno_names))
                return NULL;

        return errno_names[id];
}
#endif

const char* errno_name(int id, char buf[static ERRNO_NAME_BUF_LEN]) {
        const char *a = errno_name_no_fallback(id);
        if (a)
                return a;
        snprintf(buf, ERRNO_NAME_BUF_LEN, "%d", abs(id));
        return buf;
}
