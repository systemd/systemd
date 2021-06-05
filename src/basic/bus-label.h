/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdlib.h>

#include "string-util.h"

char *bus_label_escape(const char *s);
char *bus_label_unescape_n(const char *f, size_t l);

static inline char *bus_label_unescape(const char *f) {
        return bus_label_unescape_n(f, strlen_ptr(f));
}
