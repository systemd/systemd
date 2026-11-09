/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

_sync_ char* bus_label_escape(const char *s);
_sync_ char* bus_label_unescape_n(const char *f, size_t l);

static inline char* bus_label_unescape(const char *f) {
        return bus_label_unescape_n(f, SIZE_MAX);
}
