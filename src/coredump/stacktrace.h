/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"
#include "json.h"

void coredump_parse_core(int fd, const char *executable, char **ret);

static inline Hashmap* json_variant_hashmap_free(Hashmap *h) {
        return hashmap_free_with_destructor(h, json_variant_unrefp);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, json_variant_hashmap_free);
