/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include "string-table.h"
#include "string-util.h"

ssize_t string_table_lookup(const char * const *table, size_t len, const char *key) {
        size_t i;

        if (!key)
                return -1;

        for (i = 0; i < len; ++i)
                if (streq_ptr(table[i], key))
                        return (ssize_t) i;

        return -1;
}
