/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>
#include <sys/socket.h>

#include "af-list.h"
#include "macro.h"

static const struct af_name* lookup_af(register const char *str, register GPERF_LEN_TYPE len);

#include "af-from-name.h"
#include "af-to-name.h"

const char *af_to_name(int id) {

        if (id <= 0)
                return NULL;

        if (id >= (int) ELEMENTSOF(af_names))
                return NULL;

        return af_names[id];
}

int af_from_name(const char *name) {
        const struct af_name *sc;

        assert(name);

        sc = lookup_af(name, strlen(name));
        if (!sc)
                return AF_UNSPEC;

        return sc->id;
}

int af_max(void) {
        return ELEMENTSOF(af_names);
}
