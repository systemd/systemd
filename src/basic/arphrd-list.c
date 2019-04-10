/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <linux/if_arp.h>
#include <string.h>

#include "arphrd-list.h"
#include "macro.h"

static const struct arphrd_name* lookup_arphrd(register const char *str, register GPERF_LEN_TYPE len);

#include "arphrd-from-name.h"
#include "arphrd-to-name.h"

const char *arphrd_to_name(int id) {

        if (id <= 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(arphrd_names))
                return NULL;

        return arphrd_names[id];
}

int arphrd_from_name(const char *name) {
        const struct arphrd_name *sc;

        assert(name);

        sc = lookup_arphrd(name, strlen(name));
        if (!sc)
                return -EINVAL;

        return sc->id;
}

int arphrd_max(void) {
        return ELEMENTSOF(arphrd_names);
}
