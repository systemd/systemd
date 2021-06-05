/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

const char* af_to_ipv4_ipv6(int id);
int af_from_ipv4_ipv6(const char *af);

int af_max(void);
