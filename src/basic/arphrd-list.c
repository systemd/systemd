/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/if_arp.h>
#include <string.h>

#include "arphrd-list.h"
#include "macro.h"

static const struct arphrd_name* lookup_arphrd(register const char *str, register GPERF_LEN_TYPE len);

#include "arphrd-from-name.h"
#include "arphrd-to-name.h"

int arphrd_from_name(const char *name) {
        const struct arphrd_name *sc;

        assert(name);

        sc = lookup_arphrd(name, strlen(name));
        if (!sc)
                return -EINVAL;

        return sc->id;
}
