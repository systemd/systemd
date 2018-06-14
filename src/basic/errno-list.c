/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <string.h>

#include "errno-list.h"
#include "macro.h"

static const struct errno_name* lookup_errno(register const char *str,
                                             register GPERF_LEN_TYPE len);

#include "errno-from-name.h"
#include "errno-to-name.h"

const char *errno_to_name(int id) {

        if (id < 0)
                id = -id;

        if (id >= (int) ELEMENTSOF(errno_names))
                return NULL;

        return errno_names[id];
}

int errno_from_name(const char *name) {
        const struct errno_name *sc;

        assert(name);

        sc = lookup_errno(name, strlen(name));
        if (!sc)
                return -EINVAL;

        assert(sc->id > 0);
        return sc->id;
}
