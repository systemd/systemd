/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/socket.h>

#include "string-util.h"

const char *af_to_name(int id);
int af_from_name(const char *name);

static inline const char* af_to_name_short(int id) {
        const char *f;

        if (id == AF_UNSPEC)
                return "*";

        f = af_to_name(id);
        if (!f)
                return "unknown";

        assert(startswith(f, "AF_"));
        return f + 3;
}

int af_max(void);
